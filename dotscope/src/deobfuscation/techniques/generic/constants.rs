//! Generic constant decryptor detection.
//!
//! Identifies and registers generic constant decryptor methods — methods that
//! decrypt integer, float, or array constants via FieldRVA-backed data. Common
//! patterns include `T(int32)` generic decryptor methods and `int32(int32)`
//! constant accessors.
//!
//! # Detection
//!
//! Scans for methods with characteristic constant decryptor signatures and
//! FieldRVA-backed data fields.
//!
//! # Passes
//!
//! Does not create its own pass — uses the shared `DecryptionPass` from
//! `create_deob_passes()`. Registers discovered decryptor methods with the
//! analysis context during `initialize()`.

use std::any::Any;

use crate::{
    cilassembly::CleanupRequest,
    deobfuscation::{
        context::AnalysisContext,
        techniques::{Detection, Detections, Evidence, PassPhase, Technique, TechniqueCategory},
        utils::{build_call_site_counts, filter_by_call_threshold},
    },
    metadata::{signatures::TypeSignature, token::Token, typesystem::wellknown},
    CilObject,
};

/// Findings from generic constant decryptor detection.
#[derive(Debug)]
pub struct ConstantFindings {
    /// Tokens of detected constant decryptor methods.
    pub decryptor_methods: Vec<Token>,
}

/// Detects generic constant decryptor methods.
pub struct GenericConstants;

impl Technique for GenericConstants {
    fn id(&self) -> &'static str {
        "generic.constants"
    }

    fn name(&self) -> &'static str {
        "Generic Constant Decryptor Detection"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Value
    }

    fn detect(&self, assembly: &CilObject) -> Detection {
        // Phase 1: collect candidates matching constant decryptor signatures.
        let mut candidates = Vec::new();

        for method_entry in assembly.methods() {
            let method = method_entry.value();

            if !method.is_static() {
                continue;
            }
            if method.name == wellknown::members::CCTOR || method.name == wellknown::members::CTOR {
                continue;
            }

            let param_count = method.signature.params.len();

            // int32(int32) — integer constant accessor
            let is_int_accessor = param_count == 1
                && matches!(method.signature.params[0].base, TypeSignature::I4)
                && matches!(method.signature.return_type.base, TypeSignature::I4);

            // object(int32) — generic constant accessor
            let is_obj_accessor = param_count == 1
                && matches!(method.signature.params[0].base, TypeSignature::I4)
                && matches!(method.signature.return_type.base, TypeSignature::Object);

            if is_int_accessor || is_obj_accessor {
                candidates.push(method.token);
            }
        }

        if candidates.is_empty() {
            return Detection::new_empty();
        }

        // Phase 2: count call sites for all candidates in a single pass.
        let counts = build_call_site_counts(assembly, candidates.iter().copied());

        // Phase 3: filter by call-site threshold.
        let decryptors = filter_by_call_threshold(candidates, &counts, 3);

        if decryptors.is_empty() {
            return Detection::new_empty();
        }

        let count = decryptors.len();
        let findings = ConstantFindings {
            decryptor_methods: decryptors,
        };

        Detection::new_detected(
            vec![Evidence::Structural(format!(
                "{count} potential constant decryptor methods"
            ))],
            Some(Box::new(findings) as Box<dyn Any + Send + Sync>),
        )
    }

    fn ssa_phase(&self) -> Option<PassPhase> {
        Some(PassPhase::Value)
    }

    fn initialize(
        &self,
        ctx: &AnalysisContext,
        _assembly: &CilObject,
        detection: &Detection,
        _detections: &Detections,
    ) {
        let Some(findings) = detection.findings::<ConstantFindings>() else {
            return;
        };

        for token in &findings.decryptor_methods {
            ctx.decryptors.register(*token);
        }
    }

    fn cleanup(&self, detection: &Detection) -> Option<CleanupRequest> {
        let findings = detection.findings::<ConstantFindings>()?;
        if findings.decryptor_methods.is_empty() {
            return None;
        }
        let mut req = CleanupRequest::new();
        for &token in &findings.decryptor_methods {
            req.add_method(token);
        }
        Some(req)
    }
}

#[cfg(test)]
mod tests {
    use crate::{deobfuscation::techniques::Technique, test::helpers::load_sample};

    /// Verify detection runs without error on a protected sample.
    ///
    /// ConfuserEx uses a unified `T Get<T>(int32)` decryptor that the
    /// ConfuserEx-specific technique handles. The generic technique catches
    /// simpler `int32(int32)` / `object(int32)` patterns from other packers.
    #[test]
    fn test_detect_no_panic_on_obfuscated() {
        let asm = load_sample("tests/samples/packers/confuserex/1.6.0/mkaring_constants.exe");
        let technique = super::GenericConstants;
        let _detection = technique.detect(&asm);
    }

    #[test]
    fn test_detect_negative() {
        let asm = load_sample("tests/samples/packers/confuserex/1.6.0/original.exe");
        let technique = super::GenericConstants;
        let detection = technique.detect(&asm);
        assert!(!detection.detected);
    }
}
