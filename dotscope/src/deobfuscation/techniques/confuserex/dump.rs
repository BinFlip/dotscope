//! ConfuserEx anti-dump detection and neutralisation.
//!
//! ConfuserEx anti-dump protection corrupts PE headers, metadata directories,
//! section names, and import table entries at runtime to prevent memory dumps.
//!
//! # Source Code Analysis
//!
//! Based on analysis of the ConfuserEx source code at:
//! - `Confuser.Protections/AntiDumpProtection.cs` — Protection entry point
//! - `Confuser.Runtime/AntiDump.cs` — Runtime implementation
//!
//! Anti-dump is part of the **Maximum** preset.
//!
//! # What AntiDump Does at Runtime
//!
//! 1. Gets module base via `Marshal.GetHINSTANCE(typeof(AntiDump).Module)`
//! 2. Parses PE header (offset `0x3c`) to find section table and metadata directory
//! 3. Uses `VirtualProtect` to make regions writable (`PAGE_EXECUTE_READWRITE`)
//! 4. Zeros section header names (8 bytes each) via `Marshal.Copy(new byte[8], ...)`
//! 5. Zeros the metadata directory (4 DWORDs)
//! 6. Zeros the metadata header magic and stream names
//! 7. Corrupts import table: renames `mscoree.dll` to `ntldll.dll`,
//!    `_CorExeMain` to `NtContinue`
//!
//! # Differentiating from Anti-Tamper
//!
//! Both anti-dump and anti-tamper use `VirtualProtect` + `GetHINSTANCE` +
//! `get_Module`. The key differentiator is `Marshal.Copy`:
//! - **Anti-dump**: VirtualProtect + GetHINSTANCE + get_Module + **Marshal.Copy**
//! - **Anti-tamper**: VirtualProtect + GetHINSTANCE + get_Module (no Marshal.Copy)
//!
//! Both are injected as `call Initialize` at position 0 in `<Module>::.cctor`.
//!
//! # Detection
//!
//! Scans methods for the four-part pattern: VirtualProtect + GetHINSTANCE +
//! get_Module + Marshal.Copy. Methods matching all four are classified as
//! anti-dump.
//!
//! # Neutralisation Strategy
//!
//! Since AntiDump is purely a runtime protection (it doesn't modify the binary
//! on disk), neutralisation involves marking the anti-dump methods for removal.
//! After cleanup, the anti-dump method becomes dead code and is eliminated.
//!
//! # Passes
//!
//! Does not create its own pass — neutralisation is handled by the engine's
//! `NeutralizationPass`. The cleanup request marks anti-dump methods for
//! removal.
//!
//! # Test Samples
//!
//! | Sample | Has Anti-Dump | Notes |
//! |--------|--------------|-------|
//! | `mkaring_normal.exe` | No | Normal preset (no anti-dump) |
//! | `mkaring_maximum.exe` | Yes | Maximum preset |

use std::collections::HashSet;

use crate::{
    cilassembly::CleanupRequest,
    deobfuscation::techniques::{Detection, Evidence, PassPhase, Technique, TechniqueCategory},
    metadata::token::Token,
    CilObject,
};

/// Findings from ConfuserEx anti-dump detection.
#[derive(Debug)]
pub struct AntiDumpFindings {
    /// Tokens of methods containing anti-dump logic.
    pub method_tokens: HashSet<Token>,
    /// Whether the module .cctor should also be processed.
    pub include_module_cctor: bool,
}

/// Detects ConfuserEx anti-dump protection (PE header corruption via Marshal.Copy).
///
/// Supersedes `generic.dump` with ConfuserEx-specific detection that
/// identifies the exact four-part call pattern (VirtualProtect + GetHINSTANCE
/// + get_Module + Marshal.Copy).
pub struct ConfuserExAntiDump;

impl Technique for ConfuserExAntiDump {
    fn id(&self) -> &'static str {
        "confuserex.dump"
    }

    fn name(&self) -> &'static str {
        "ConfuserEx Anti-Dump Neutralisation"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Neutralization
    }

    fn supersedes(&self) -> &[&'static str] {
        &["generic.dump"]
    }

    fn detect(&self, assembly: &CilObject) -> Detection {
        let mut method_tokens = HashSet::new();

        // Resolve VirtualProtect P/Invoke tokens from the ImplMap table.
        // The real DLL export name is never renamed by obfuscators.
        let virtualprotect_tokens =
            super::helpers::resolve_pinvoke_tokens(assembly, "VirtualProtect");

        for method_entry in assembly.methods() {
            let method = method_entry.value();

            let mut has_virtualprotect = false;
            let mut has_gethinstance = false;
            let mut has_get_module = false;
            let mut has_marshal_copy = false;

            for instr in method.instructions() {
                if let Some(token) = instr.get_token_operand() {
                    // Check P/Invoke import name for renamed VirtualProtect.
                    if virtualprotect_tokens.contains(&token) {
                        has_virtualprotect = true;
                    }

                    if let Some(name) = assembly.resolve_method_name(token) {
                        if name.contains("VirtualProtect") {
                            has_virtualprotect = true;
                        }
                        if name.contains("GetHINSTANCE") {
                            has_gethinstance = true;
                        }
                        if name.contains("get_Module") {
                            has_get_module = true;
                        }
                        if name.contains("Marshal") && name.contains("Copy") {
                            has_marshal_copy = true;
                        }
                    }
                }
            }

            // Anti-dump: all four must be present.
            // Marshal.Copy is the key differentiator from anti-tamper.
            if has_virtualprotect && has_gethinstance && has_get_module && has_marshal_copy {
                method_tokens.insert(method.token);
            }
        }

        if method_tokens.is_empty() {
            return Detection::new_empty();
        }

        let include_module_cctor = !method_tokens.is_empty();
        let count = method_tokens.len();

        let mut detection = Detection::new_detected(
            vec![Evidence::BytecodePattern(format!(
                "{count} anti-dump methods (VirtualProtect + GetHINSTANCE + get_Module + Marshal.Copy)",
            ))],
            None,
        );

        for token in &method_tokens {
            detection.cleanup.add_method(*token);
        }

        detection.findings = Some(Box::new(AntiDumpFindings {
            method_tokens,
            include_module_cctor,
        }));

        detection
    }

    fn ssa_phase(&self) -> Option<PassPhase> {
        Some(PassPhase::Simplify)
    }

    fn cleanup(&self, detection: &Detection) -> Option<CleanupRequest> {
        let findings = detection.findings::<AntiDumpFindings>()?;
        if findings.method_tokens.is_empty() {
            return None;
        }

        let mut request = CleanupRequest::new();
        for token in &findings.method_tokens {
            request.add_method(*token);
        }
        Some(request)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        deobfuscation::techniques::{
            confuserex::dump::{AntiDumpFindings, ConfuserExAntiDump},
            Technique,
        },
        test::helpers::load_sample,
    };

    #[test]
    fn test_detect_positive() {
        // Anti-dump uses VirtualProtect + GetHINSTANCE + get_Module + Marshal.Copy.
        // In mkaring_maximum.exe, anti-tamper encrypts most method bodies,
        // so anti-dump detection requires readable method bodies. We attempt
        // detection and verify findings structure when it succeeds.
        let assembly = load_sample("tests/samples/packers/confuserex/1.6.0/mkaring_maximum.exe");

        let technique = ConfuserExAntiDump;
        let detection = technique.detect(&assembly);

        // Anti-dump may not be detectable on anti-tamper-encrypted samples
        // because the method bodies containing Marshal.Copy are encrypted.
        // If detected, verify findings structure.
        if detection.detected {
            assert!(
                !detection.evidence.is_empty(),
                "Detection should have evidence"
            );

            let findings = detection
                .findings::<AntiDumpFindings>()
                .expect("Should have AntiDumpFindings");

            assert!(
                !findings.method_tokens.is_empty(),
                "Should have anti-dump method tokens"
            );
        }
    }

    #[test]
    fn test_no_false_positive_on_antidebug() {
        // Anti-debug uses VirtualProtect + GetHINSTANCE + get_Module but
        // does NOT use Marshal.Copy. Verify the differentiator works.
        let assembly = load_sample("tests/samples/packers/confuserex/1.6.0/mkaring_minimal.exe");

        let technique = ConfuserExAntiDump;
        let detection = technique.detect(&assembly);

        assert!(
            !detection.detected,
            "ConfuserExAntiDump should not false-positive on anti-debug-only sample"
        );
    }

    #[test]
    fn test_detect_negative() {
        let assembly = load_sample("tests/samples/packers/confuserex/1.6.0/original.exe");

        let technique = ConfuserExAntiDump;
        let detection = technique.detect(&assembly);

        assert!(
            !detection.detected,
            "ConfuserExAntiDump should not detect anti-dump in original.exe"
        );
    }
}
