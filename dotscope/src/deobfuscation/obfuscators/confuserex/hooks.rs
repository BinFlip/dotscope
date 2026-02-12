//! `ConfuserEx`-specific emulation hooks.
//!
//! This module provides hooks for intercepting and handling `ConfuserEx`-specific
//! method patterns during emulation, such as inline LZMA decompression.
//!
//! # LZMA Decompression Hook
//!
//! `ConfuserEx` embeds an inline LZMA decompressor that doesn't use the BCL.
//! The [`create_lzma_hook`] function creates a hook that:
//!
//! 1. Matches internal methods with signature `byte[] -> byte[]`
//! 2. Checks if the input data has a `ConfuserEx` LZMA header
//! 3. Decompresses natively instead of emulating the complex LZMA algorithm
//!
//! This dramatically speeds up resource decryption by avoiding thousands of
//! emulated instructions for the LZMA decompression loop.
//!
//! # Anti-Tamper Stub Hook
//!
//! After anti-tamper byte-level deobfuscation, the anti-tamper initialization
//! methods should not be executed again during warmup emulation. The
//! [`create_anti_tamper_stub_hook`] function creates a hook that stubs out
//! these methods to prevent them from corrupting state.

use std::{collections::HashSet, hash::BuildHasher, sync::Arc};

use crate::{
    emulation::{EmValue, EmulationThread, Hook, HookContext, HookPriority, PreHookResult},
    metadata::{tables::TableId, token::Token, typesystem::CilFlavor},
    utils::{decompress_confuserex_lzma, is_confuserex_lzma},
};

/// Creates a hook for native `ConfuserEx` LZMA decompression.
///
/// This hook intercepts internal methods that match the LZMA decompressor pattern:
/// - Internal method (`MethodDef`, not external BCL)
/// - Signature: `byte[] MethodName(byte[])` or `static byte[] MethodName(byte[])`
/// - Input data starts with `ConfuserEx` LZMA header (0x5D followed by dictionary size)
///
/// When matched, the hook decompresses the data natively using the `lzma-rs` crate
/// instead of emulating the complex LZMA algorithm instruction-by-instruction.
///
/// # Returns
///
/// A [`Hook`] configured with appropriate matchers and a pre-hook handler that
/// performs native decompression.
///
/// # Example
///
/// ```ignore
/// use dotscope::deobfuscation::obfuscators::confuserex::hooks::create_lzma_hook;
/// use dotscope::emulation::ProcessBuilder;
///
/// let process = ProcessBuilder::new()
///     .assembly(assembly)
///     .with_hook(create_lzma_hook())
///     .build()?;
/// ```
#[must_use]
pub fn create_lzma_hook() -> Hook {
    Hook::new("confuserex-lzma-decompressor")
        .with_priority(HookPriority::HIGH) // Run before generic handlers
        .match_internal_method() // Only internal MethodDef, not external BCL
        .match_runtime("lzma-candidate-check", is_lzma_decompressor_candidate)
        .pre(lzma_decompression_handler)
}

/// Creates a hook that stubs out protection initialization methods.
///
/// After anti-tamper byte-level deobfuscation has decrypted method bodies,
/// the protection initialization methods (anti-tamper, anti-debug, resource handlers)
/// should not be executed during warmup emulation. If they were to run, they would
/// attempt to access data that has already been modified/consumed by the byte-level
/// deobfuscation, or perform P/Invoke calls that aren't supported in emulation.
///
/// This hook intercepts calls to the specified method tokens and immediately returns
/// an appropriate default value based on the method's return type.
///
/// # Arguments
///
/// * `tokens` - Set of protection method tokens to stub out (typically from
///   `DeobfuscationFindings` - `anti_tamper`, `anti_debug`, resource handlers)
///
/// # Returns
///
/// A [`Hook`] that bypasses execution of the specified methods.
///
/// # Example
///
/// ```ignore
/// use dotscope::deobfuscation::{create_anti_tamper_stub_hook, detect_confuserex};
/// use dotscope::emulation::ProcessBuilder;
///
/// let (_, findings) = detect_confuserex(&assembly);
/// let stub_tokens: HashSet<Token> = findings.anti_tamper_methods
///     .iter()
///     .chain(findings.anti_debug_methods.iter())
///     .map(|(_, t)| *t)
///     .collect();
///
/// let process = ProcessBuilder::new()
///     .assembly(assembly)
///     .hook(create_anti_tamper_stub_hook(stub_tokens))
///     .build()?;
/// ```
#[must_use]
pub fn create_anti_tamper_stub_hook<S: BuildHasher + Send + Sync + 'static>(
    tokens: HashSet<Token, S>,
) -> Hook {
    let tokens = Arc::new(tokens);

    Hook::new("confuserex-protection-stub")
        .with_priority(HookPriority::HIGHEST) // Highest priority - always match first
        .match_runtime("protection-token-check", {
            let tokens = Arc::clone(&tokens);
            move |ctx: &HookContext<'_>, _thread: &EmulationThread| {
                // Check if this is an internal method (MethodDef table = 0x06)
                // and if the token is in our stub set
                let is_methoddef = ctx.method_token.is_table(TableId::MethodDef);
                is_methoddef && tokens.contains(&ctx.method_token)
            }
        })
        .pre(|ctx, _thread| {
            // Return an appropriate default value based on the method's return type.
            // This prevents stack underflow when the caller expects a return value.
            let return_value = match ctx.return_type {
                None | Some(CilFlavor::Void) => None, // Void method
                Some(
                    CilFlavor::Boolean // false
                    | CilFlavor::I1 | CilFlavor::U1
                    | CilFlavor::I2 | CilFlavor::U2 | CilFlavor::Char
                    | CilFlavor::I4 | CilFlavor::U4
                    | CilFlavor::TypedRef { .. }
                    | CilFlavor::Unknown, // Fallback
                ) => Some(EmValue::I32(0)),
                Some(CilFlavor::I8 | CilFlavor::U8) => Some(EmValue::I64(0)),
                Some(CilFlavor::R4) => Some(EmValue::F32(0.0)),
                Some(CilFlavor::R8) => Some(EmValue::F64(0.0)),
                Some(
                    CilFlavor::I | CilFlavor::U
                    | CilFlavor::Pointer | CilFlavor::ByRef
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
                Some(CilFlavor::ValueType) => {
                    // For value types, return a zeroed struct would be ideal,
                    // but EmValue::I32(0) works for small value types
                    Some(EmValue::I32(0))
                }
            };
            PreHookResult::Bypass(return_value)
        })
}

/// Checks if the method is an LZMA decompressor candidate.
///
/// A candidate must:
/// 1. Have signature `byte[] -> byte[]` (single byte array param, returns byte array)
/// 2. Have input data that looks like `ConfuserEx` LZMA format
///
/// Also supports streaming decompress methods that take byte[] but may not return byte[].
fn is_lzma_decompressor_candidate(ctx: &HookContext<'_>, thread: &EmulationThread) -> bool {
    // Check if we have a byte[] parameter (first param for static, or second for instance)
    let has_byte_array_param = match ctx.param_types {
        Some(params) if !params.is_empty() => params.iter().any(|p| {
            matches!(
                p,
                CilFlavor::Array { element_type, rank, .. }
                    if *rank == 1 && matches!(element_type.as_ref(), CilFlavor::U1 | CilFlavor::I1)
            )
        }),
        _ => false,
    };

    if !has_byte_array_param {
        return false;
    }

    // Check return type is byte[] (Array of U1/I1 with rank 1)
    // For streaming APIs, also allow void return type if we have LZMA input
    let returns_byte_array = match &ctx.return_type {
        Some(CilFlavor::Array {
            element_type, rank, ..
        }) => *rank == 1 && matches!(element_type.as_ref(), CilFlavor::U1 | CilFlavor::I1),
        _ => false,
    };

    // If it has byte[] param and returns byte[], it's a strong candidate
    // If it only has byte[] param (no byte[] return), still check for LZMA input
    if !returns_byte_array && !has_byte_array_param {
        return false;
    }

    // Check if input data looks like ConfuserEx LZMA
    is_lzma_input(ctx, thread)
}

/// Checks if any of the method's arguments contains `ConfuserEx` LZMA data.
fn is_lzma_input(ctx: &HookContext<'_>, thread: &EmulationThread) -> bool {
    // Check all arguments for byte[] containing LZMA data
    for (idx, arg) in ctx.args.iter().enumerate() {
        // Skip 'this' for instance methods
        if idx == 0 && ctx.this.is_some() {
            continue;
        }

        let EmValue::ObjectRef(heap_ref) = arg else {
            continue;
        };

        // Try to get array data from heap
        let Some(byte_data) = thread
            .heap()
            .get_array_as_bytes(*heap_ref, ctx.pointer_size)
            .or_else(|| thread.heap().get_byte_array(*heap_ref))
        else {
            continue;
        };

        // Check for ConfuserEx LZMA header
        if is_confuserex_lzma(&byte_data) {
            return true;
        }
    }

    false
}

/// Pre-hook handler that performs native LZMA decompression.
fn lzma_decompression_handler(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    // Find the byte[] argument containing LZMA data
    let mut lzma_data: Option<Vec<u8>> = None;

    for (idx, arg) in ctx.args.iter().enumerate() {
        // Skip 'this' for instance methods
        if idx == 0 && ctx.this.is_some() {
            continue;
        }

        let EmValue::ObjectRef(heap_ref) = arg else {
            continue;
        };

        // Try to get array data from heap
        let Some(byte_data) = thread
            .heap()
            .get_array_as_bytes(*heap_ref, ctx.pointer_size)
            .or_else(|| thread.heap().get_byte_array(*heap_ref))
        else {
            continue;
        };

        // Check for ConfuserEx LZMA header
        if is_confuserex_lzma(&byte_data) {
            lzma_data = Some(byte_data);
            break;
        }
    }

    let Some(byte_data) = lzma_data else {
        // No LZMA data found even though matcher thought there was.
        // This shouldn't happen, but if it does, return null to avoid stack issues.
        return PreHookResult::Bypass(Some(EmValue::Null));
    };

    // Decompress using native LZMA
    let Ok(decompressed) = decompress_confuserex_lzma(&byte_data) else {
        // Decompression failed - data looked like LZMA header but wasn't valid.
        // Return null rather than letting emulation proceed, which could cause
        // stack underflow or other issues when the hook matched but didn't handle.
        return PreHookResult::Bypass(Some(EmValue::Null));
    };

    // Allocate result as byte[] on the heap
    let elements: Vec<EmValue> = decompressed
        .into_iter()
        .map(|b| EmValue::I32(i32::from(b)))
        .collect();

    match thread
        .heap_mut()
        .alloc_array_with_values(CilFlavor::U1, elements)
    {
        Ok(result_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(result_ref))),
        Err(_) => {
            // Allocation failed - return null rather than causing stack issues
            PreHookResult::Bypass(Some(EmValue::Null))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        deobfuscation::obfuscators::confuserex::hooks::create_lzma_hook, emulation::HookPriority,
    };

    #[test]
    fn test_create_lzma_hook() {
        let hook = create_lzma_hook();
        assert_eq!(hook.name(), "confuserex-lzma-decompressor");
        assert_eq!(hook.priority(), HookPriority::HIGH);
    }
}
