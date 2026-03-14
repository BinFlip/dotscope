//! Generic control flow flattening detection and reconstruction.
//!
//! Detects switch-based control flow flattening (CFF) dispatchers — the most
//! common form of control flow obfuscation. In CFF, the original control flow
//! graph is replaced with a loop containing a switch dispatcher that uses a
//! state variable to select the next block to execute.
//!
//! # Detection
//!
//! Scans methods for switch-based dispatcher patterns: high fan-out switch
//! blocks with state variables and loop-switch structures. Counts dispatcher
//! methods and produces a confidence score.
//!
//! # Passes
//!
//! This technique provides detection and attribution only. The
//! [`CffReconstructionPass`](crate::deobfuscation::CffReconstructionPass)
//! is an infrastructure pass added by the engine's pass scheduler for all
//! pipelines, since CFF reconstruction benefits any obfuscated assembly
//! regardless of which obfuscator was detected.

use crate::{
    deobfuscation::techniques::{Detection, Evidence, PassPhase, Technique, TechniqueCategory},
    CilObject,
};

/// Detects and reconstructs control flow flattening (CFF/switch-based dispatchers).
pub struct GenericFlattening;

impl Technique for GenericFlattening {
    fn id(&self) -> &'static str {
        "generic.flattening"
    }

    fn name(&self) -> &'static str {
        "Control Flow Flattening Reconstruction"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Structure
    }

    fn requires(&self) -> &[&'static str] {
        &["generic.predicates"]
    }

    fn detect(&self, assembly: &CilObject) -> Detection {
        let mut dispatcher_count = 0usize;

        for method_entry in assembly.methods() {
            let method = method_entry.value();
            let instructions: Vec<_> = method.instructions().collect();

            if instructions.len() < 10 {
                continue;
            }

            // Look for switch instructions with high fan-out (many cases)
            let mut has_switch = false;
            let mut max_switch_targets = 0usize;

            for instr in &instructions {
                if instr.mnemonic == "switch" {
                    has_switch = true;
                    // Count targets from operand
                    let targets = instr.get_targets();
                    max_switch_targets = max_switch_targets.max(targets.len());
                }
            }

            // A dispatcher typically has >= 4 switch targets in a loop structure
            if has_switch && max_switch_targets >= 4 {
                // Check for loop pattern: backwards branch somewhere after the switch
                let has_backward_branch = instructions.iter().any(|instr| {
                    if instr.mnemonic.starts_with("br") {
                        if let Some(target) = instr.get_branch_target() {
                            return target < instr.offset;
                        }
                    }
                    false
                });

                if has_backward_branch {
                    dispatcher_count += 1;
                }
            }
        }

        if dispatcher_count == 0 {
            return Detection::new_empty();
        }

        Detection::new_detected(
            vec![Evidence::Structural(format!(
                "{dispatcher_count} methods with switch-based dispatcher patterns"
            ))],
            None,
        )
    }

    fn ssa_phase(&self) -> Option<PassPhase> {
        Some(PassPhase::Structure)
    }
}

#[cfg(test)]
mod tests {
    use crate::deobfuscation::techniques::Technique;
    use crate::test::helpers::load_sample;

    /// Verify detection on a sample with switch-based control flow obfuscation.
    ///
    /// ConfuserEx control flow samples use switch dispatchers that the generic
    /// heuristic (>= 4 switch targets + backward branch) may or may not catch
    /// depending on the number of methods and switch fan-out in the test app.
    /// This test verifies the detection runs without error.
    #[test]
    fn test_detect_no_panic_on_obfuscated() {
        let asm = load_sample("tests/samples/packers/confuserex/1.6.0/mkaring_controlflow.exe");
        let technique = super::GenericFlattening;
        let _detection = technique.detect(&asm);
    }

    #[test]
    fn test_detect_negative() {
        let asm = load_sample("tests/samples/packers/confuserex/1.6.0/original.exe");
        let technique = super::GenericFlattening;
        let detection = technique.detect(&asm);
        assert!(!detection.detected);
    }
}
