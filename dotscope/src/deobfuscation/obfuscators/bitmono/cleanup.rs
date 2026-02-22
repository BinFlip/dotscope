//! Post-deobfuscation cleanup for BitMono.
//!
//! Builds a [`CleanupRequest`] for removing BitMono protection artifacts:
//! - `SuppressIldasmAttribute` custom attribute (AntiILdasm)
//! - AntiDe4dot fake obfuscator attributes
//! - Protection infrastructure types (DotNetHook helper, string decryptor type, etc.)
//! - Decryptor methods (string encryption)
//! - Proxy methods (DotNetHook dummy and init methods)
//! - BillionNops dead methods
//! - AntiDecompiler types (invalid ExplicitLayout types)
//! - Infrastructure fields (salt/crypt key, per-string data fields)
//!
//! After these explicit removals, the orphan removal phase in the executor
//! cascades to clean up ImplMap (P/Invoke), ModuleRef (kernel32.dll, libc.so.6),
//! and AssemblyRef (System.Private.CoreLib) entries that become unreferenced.

use crate::{
    cilassembly::CleanupRequest,
    deobfuscation::{
        cleanup::{add_safe_methods, create_cleanup_request},
        context::AnalysisContext,
        findings::DeobfuscationFindings,
    },
    CilObject,
};

/// Builds a cleanup request for BitMono artifacts.
///
/// This is the main entry point called by `BitMonoObfuscator::cleanup_request()`.
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

    // Remove SuppressIldasmAttribute (AntiILdasm)
    if let Some(token) = findings.suppress_ildasm_token {
        request.add_attribute(token);
    }

    // Remove AntiDe4dot fake attributes
    request.add_attributes_from(&findings.marker_attribute_tokens);

    if ctx.config.cleanup.remove_protection_methods {
        // Remove protection infrastructure types (DotNetHook helper, decryptor host type, etc.)
        request.add_types_from(&findings.protection_infrastructure_types);

        // Remove proxy methods (DotNetHook dummy methods and init methods)
        // Entry point check prevents removal of public API methods
        add_safe_methods(&mut request, assembly, &findings.proxy_methods, aggressive);

        if let Some(bm) = findings.bitmono() {
            // Remove BillionNops dead methods — these are definitively obfuscator-injected
            // dead code (100K+ nops) and should always be removed. No entry point check
            // needed since they cannot be real API methods.
            request.add_methods_from(&bm.billion_nops_methods);

            // Remove AntiDecompiler types (invalid Sealed|ExplicitLayout nested types)
            request.add_types_from(&bm.anti_decompiler_types);
        }

        // Remove infrastructure fields (salt/crypt key fields, per-string data fields)
        request.add_fields_from(&findings.infrastructure_fields);
    }

    if ctx.config.cleanup.remove_decryptors {
        // Remove decryptor methods (string encryption)
        add_safe_methods(
            &mut request,
            assembly,
            &findings.decryptor_methods,
            aggressive,
        );

        // Remove constant data fields (FieldRVA-backed encrypted byte arrays)
        request.add_fields_from(&findings.constant_data_fields);

        // Remove constant data types (ExplicitLayout value types backing FieldRVA data)
        request.add_types_from(&findings.constant_data_types);
    }

    if request.has_deletions() {
        Some(request)
    } else {
        None
    }
}
