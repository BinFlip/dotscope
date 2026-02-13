//! Post-deobfuscation cleanup for Obfuscar.
//!
//! Builds a [`CleanupRequest`] for removing Obfuscar protection artifacts:
//! - `<PrivateImplementationDetails>{GUID}` helper type(s) and nested types
//! - `SuppressIldasmAttribute` custom attribute
//! - Per-string accessor methods (dead after call site replacement)
//! - Infrastructure fields (encrypted data fields)

use crate::{
    cilassembly::CleanupRequest,
    deobfuscation::{
        cleanup::is_entry_point, context::AnalysisContext, findings::DeobfuscationFindings,
    },
    CilObject,
};

/// Builds a cleanup request for Obfuscar artifacts.
///
/// This is the main entry point called by `ObfuscarObfuscator::cleanup_request()`.
/// Returns a [`CleanupRequest`] specifying which types, methods, fields, and attributes
/// to remove from the deobfuscated assembly.
///
/// # Returns
///
/// `Some(CleanupRequest)` if there are artifacts to remove, `None` if cleanup is
/// disabled or no deletions are needed.
pub fn build_request(
    assembly: &CilObject,
    ctx: &AnalysisContext,
    findings: &DeobfuscationFindings,
) -> Option<CleanupRequest> {
    let cleanup_config = &ctx.config.cleanup;
    if !cleanup_config.any_enabled() {
        return None;
    }

    let request = build_cleanup_request(findings, assembly, ctx);

    if request.has_deletions() {
        Some(request)
    } else {
        None
    }
}

/// Collects tokens to remove from Obfuscar findings into a [`CleanupRequest`].
///
/// Processes findings in order:
/// 1. **Infrastructure types** — `<PrivateImplementationDetails>{GUID}` helper type(s)
///    and nested types (if `remove_protection_methods` enabled)
/// 2. **SuppressIldasmAttribute** — the custom attribute token (always removed if present)
/// 3. **Decryptor methods** — registered decryptors from `ctx.decryptors` and accessor
///    methods from findings (if `remove_decryptors`/`remove_protection_methods` enabled)
/// 4. **Infrastructure fields** — encrypted data fields "3", "4", "5" in the helper type
///    (if `remove_protection_methods` enabled)
///
/// Entry point methods are never removed regardless of cleanup settings.
fn build_cleanup_request(
    findings: &DeobfuscationFindings,
    assembly: &CilObject,
    ctx: &AnalysisContext,
) -> CleanupRequest {
    let mut request = CleanupRequest::with_settings(
        ctx.config.cleanup.remove_orphan_metadata,
        ctx.config.cleanup.remove_empty_types,
    );
    let aggressive = ctx.config.cleanup.remove_unused_methods;

    // 1. Remove protection infrastructure types (<PrivateImplementationDetails>{GUID})
    if ctx.config.cleanup.remove_protection_methods {
        for (_, type_token) in &findings.protection_infrastructure_types {
            request.add_type(*type_token);
        }
    }

    // 2. Remove SuppressIldasmAttribute
    if let Some(token) = findings.suppress_ildasm_token {
        request.add_attribute(token);
    }

    // 3. Remove decryptor/accessor methods
    if ctx.config.cleanup.remove_decryptors {
        for token in ctx.decryptors.removable_decryptors() {
            if !is_entry_point(assembly, token, aggressive) {
                request.add_method(token);
            }
        }
    }

    // Also remove decryptor methods from detection findings
    if ctx.config.cleanup.remove_protection_methods {
        for (_, token) in &findings.decryptor_methods {
            if !is_entry_point(assembly, *token, aggressive) {
                request.add_method(*token);
            }
        }
    }

    // 4. Remove infrastructure fields (fields 3, 4, 5 in helper type)
    if ctx.config.cleanup.remove_protection_methods {
        for (_, field_token) in &findings.infrastructure_fields {
            request.add_field(*field_token);
        }
    }

    request
}
