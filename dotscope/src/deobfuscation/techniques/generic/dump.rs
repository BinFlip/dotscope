//! Generic anti-dump detection.
//!
//! Detects anti-dump protections that corrupt PE headers at runtime via
//! `VirtualProtect` to prevent memory dumping. Distinguished from anti-tamper
//! by the absence of `Marshal.Copy` (anti-tamper uses Marshal.Copy for
//! method body decryption).
//!
//! # Detection
//!
//! Scans for VirtualProtect + PE header manipulation patterns without
//! Marshal.Copy.
//!
//! # Passes
//!
//! Does not create its own pass — neutralization is handled by the engine.

use std::collections::HashSet;

use crate::{
    cilassembly::CleanupRequest,
    deobfuscation::techniques::{Detection, Evidence, PassPhase, Technique, TechniqueCategory},
    metadata::token::Token,
    CilObject,
};

/// Findings from generic anti-dump detection.
#[derive(Debug)]
pub struct AntiDumpFindings {
    /// Tokens of methods containing anti-dump logic.
    pub method_tokens: HashSet<Token>,
}

/// Detects anti-dump protections (PE header corruption via VirtualProtect).
pub struct GenericAntiDump;

impl Technique for GenericAntiDump {
    fn id(&self) -> &'static str {
        "generic.dump"
    }

    fn name(&self) -> &'static str {
        "Generic Anti-Dump Detection"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Neutralization
    }

    fn detect(&self, assembly: &CilObject) -> Detection {
        let mut method_tokens = HashSet::new();

        for method_entry in assembly.methods() {
            let method = method_entry.value();

            let mut has_virtual_protect = false;
            let mut has_get_hinstance = false;
            let mut has_marshal_copy = false;

            for instr in method.instructions() {
                if let Some(token) = instr.get_token_operand() {
                    if let Some(name) = assembly.resolve_method_name(token) {
                        if name.contains("VirtualProtect") {
                            has_virtual_protect = true;
                        }
                        if name.contains("GetHINSTANCE") || name.contains("get_Module") {
                            has_get_hinstance = true;
                        }
                        if name.contains("Marshal") && name.contains("Copy") {
                            has_marshal_copy = true;
                        }
                    }
                }
            }

            // Anti-dump: VirtualProtect + GetHINSTANCE, but NOT Marshal.Copy
            // (Marshal.Copy distinguishes anti-tamper from anti-dump)
            if has_virtual_protect && has_get_hinstance && !has_marshal_copy {
                method_tokens.insert(method.token);
            }
        }

        if method_tokens.is_empty() {
            return Detection::new_empty();
        }

        let count = method_tokens.len();
        let mut detection = Detection::new_detected(
            vec![Evidence::BytecodePattern(format!(
                "{count} methods with anti-dump patterns (VirtualProtect without Marshal.Copy)"
            ))],
            None,
        );

        for token in &method_tokens {
            detection.cleanup.add_method(*token);
        }

        detection.findings = Some(Box::new(AntiDumpFindings { method_tokens }));

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
    use crate::{deobfuscation::techniques::Technique, test::helpers::load_sample};

    /// Verify detection runs without error on a protected sample.
    ///
    /// ConfuserEx anti-dump uses VirtualProtect + GetHINSTANCE + Marshal.Copy,
    /// which the ConfuserEx-specific technique handles. The generic technique
    /// catches the VirtualProtect + GetHINSTANCE pattern WITHOUT Marshal.Copy,
    /// which is used by other packers. In ConfuserEx samples, the presence of
    /// Marshal.Copy causes the generic technique to correctly skip them.
    #[test]
    fn test_detect_no_panic_on_obfuscated() {
        let asm = load_sample("tests/samples/packers/confuserex/1.6.0/mkaring_normal.exe");
        let technique = super::GenericAntiDump;
        let _detection = technique.detect(&asm);
    }

    #[test]
    fn test_detect_negative() {
        let asm = load_sample("tests/samples/packers/confuserex/1.6.0/original.exe");
        let technique = super::GenericAntiDump;
        let detection = technique.detect(&asm);
        assert!(!detection.detected);
    }
}
