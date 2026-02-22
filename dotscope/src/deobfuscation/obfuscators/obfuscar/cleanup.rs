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
        cleanup::{add_safe_methods, create_cleanup_request, is_entry_point},
        context::AnalysisContext,
        findings::DeobfuscationFindings,
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
    let mut request = create_cleanup_request(ctx)?;

    let aggressive = ctx.config.cleanup.remove_unused_methods;

    // 1. Remove protection infrastructure types (<PrivateImplementationDetails>{GUID})
    if ctx.config.cleanup.remove_protection_methods {
        request.add_types_from(&findings.protection_infrastructure_types);
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
        add_safe_methods(
            &mut request,
            assembly,
            &findings.decryptor_methods,
            aggressive,
        );
    }

    // 4. Remove infrastructure fields (fields 3, 4, 5 in helper type)
    if ctx.config.cleanup.remove_protection_methods {
        request.add_fields_from(&findings.infrastructure_fields);
    }

    if request.has_deletions() {
        Some(request)
    } else {
        None
    }
}
