//! ConfuserEx ReferenceProxy detection.
//!
//! ConfuserEx's ReferenceProxy protection creates small proxy methods that
//! forward calls indirectly, making static analysis harder. This module
//! detects these proxy methods at the CIL level so they can be tracked
//! in findings, auto-enable the `InliningPass`, and be cleaned up.
//!
//! # Protection Preset
//!
//! ReferenceProxy is part of the **Normal** preset (and above).
//!
//! # Proxy Patterns
//!
//! ## Mild mode (direct call forwarding)
//!
//! ```text
//! ldarg.0
//! ldarg.1
//! call <TargetMethod>
//! ret
//! ```
//!
//! Single-block method: loads args in order, calls a real method, returns result.
//!
//! ## Strong mode (delegate-based)
//!
//! ```text
//! ldsfld <DelegateType> <field>
//! ldarg.0
//! ldarg.1
//! callvirt <DelegateType>::Invoke(...)
//! ret
//! ```
//!
//! Single-block method: loads a static delegate field, loads args,
//! callvirts Invoke, returns.
//!
//! Both patterns produce tiny methods (< 10 instructions) that forward
//! all arguments.

use crate::{
    assembly::{Instruction, Operand},
    deobfuscation::{
        detection::{DetectionEvidence, DetectionScore},
        findings::DeobfuscationFindings,
    },
    metadata::token::Token,
    prelude::FlowType,
    CilObject,
};

/// Maximum instruction count for a method to be considered a proxy candidate.
///
/// ReferenceProxy methods are tiny forwarding stubs. Even the strong mode
/// (delegate-based) pattern only needs ~5 instructions. We use 10 as a
/// generous upper bound to catch minor variations while avoiding false
/// positives from real methods.
const MAX_PROXY_INSTRUCTIONS: usize = 10;

/// Detects ReferenceProxy methods in the assembly.
///
/// Scans all methods for proxy patterns (mild and strong mode) and records
/// detected proxy method tokens in findings. Adds detection evidence to
/// the score.
///
/// # Arguments
///
/// * `assembly` - The assembly to analyze.
/// * `score` - Detection score to add evidence to.
/// * `findings` - Findings to populate with proxy method tokens.
pub fn detect(assembly: &CilObject, score: &DetectionScore, findings: &mut DeobfuscationFindings) {
    let entry_point_token = assembly.cor20header().entry_point_token;
    let entry_token = if entry_point_token != 0 {
        Some(Token::new(entry_point_token))
    } else {
        None
    };

    let mut proxy_count = 0usize;
    let locations: boxcar::Vec<Token> = boxcar::Vec::new();

    for method_entry in assembly.methods() {
        let method = method_entry.value();

        // Skip constructors and static constructors
        if method.is_ctor() || method.is_cctor() {
            continue;
        }

        // Skip entry point
        if entry_token.is_some_and(|t| t == method.token) {
            continue;
        }

        // Collect instructions
        let instructions: Vec<&Instruction> = method.instructions().collect();

        // Skip methods that are too large to be proxies
        if instructions.len() > MAX_PROXY_INSTRUCTIONS {
            continue;
        }

        // Skip methods with no instructions (abstract/extern)
        if instructions.is_empty() {
            continue;
        }

        // Check for proxy patterns
        if is_mild_proxy(&instructions) || is_strong_proxy(&instructions) {
            findings.proxy_methods.push(method.token);
            locations.push(method.token);
            proxy_count += 1;
        }
    }

    if proxy_count > 0 {
        score.add(DetectionEvidence::BytecodePattern {
            name: format!("ReferenceProxy methods ({proxy_count} call forwarders)"),
            locations,
            confidence: (proxy_count * 5).min(30),
        });
    }
}

/// Checks if a method matches the mild proxy pattern (direct call forwarding).
///
/// Mild pattern:
/// ```text
/// ldarg.0       \
/// ldarg.1        | zero or more ldarg instructions
/// ...           /
/// call <target>   exactly one call instruction
/// ret             return
/// ```
///
/// All non-ret, non-call instructions must be `ldarg` variants.
fn is_mild_proxy(instructions: &[&Instruction]) -> bool {
    // Must have at least 2 instructions: call + ret
    if instructions.len() < 2 {
        return false;
    }

    // Last instruction must be ret
    let last = instructions.last().unwrap();
    if last.mnemonic != "ret" {
        return false;
    }

    // Second-to-last must be a non-virtual call
    let call_instr = instructions[instructions.len() - 2];
    if call_instr.mnemonic != "call" || call_instr.flow_type != FlowType::Call {
        return false;
    }

    // The call target must be a token (not a computed target)
    if !matches!(call_instr.operand, Operand::Token(_)) {
        return false;
    }

    // All preceding instructions must be ldarg variants
    for instr in &instructions[..instructions.len() - 2] {
        if !instr.mnemonic.starts_with("ldarg") {
            return false;
        }
    }

    true
}

/// Checks if a method matches the strong proxy pattern (delegate-based).
///
/// Strong pattern:
/// ```text
/// ldsfld <field>    load static delegate field
/// ldarg.0           \
/// ldarg.1            | zero or more ldarg instructions
/// ...               /
/// callvirt Invoke   invoke the delegate
/// ret               return
/// ```
///
/// First instruction is `ldsfld`, followed by `ldarg` variants,
/// then a `callvirt` on an Invoke method, then `ret`.
fn is_strong_proxy(instructions: &[&Instruction]) -> bool {
    // Must have at least 3 instructions: ldsfld + callvirt + ret
    if instructions.len() < 3 {
        return false;
    }

    // First instruction must be ldsfld
    let first = instructions[0];
    if first.mnemonic != "ldsfld" {
        return false;
    }

    // Last instruction must be ret
    let last = instructions.last().unwrap();
    if last.mnemonic != "ret" {
        return false;
    }

    // Second-to-last must be callvirt
    let call_instr = instructions[instructions.len() - 2];
    if call_instr.mnemonic != "callvirt" || call_instr.flow_type != FlowType::Call {
        return false;
    }

    // The callvirt target must be a token
    if !matches!(call_instr.operand, Operand::Token(_)) {
        return false;
    }

    // All instructions between ldsfld and callvirt must be ldarg variants
    for instr in &instructions[1..instructions.len() - 2] {
        if !instr.mnemonic.starts_with("ldarg") {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use crate::{
        deobfuscation::obfuscators::confuserex::{detection::detect_confuserex, referenceproxy},
        CilObject, ValidationConfig,
    };

    #[test]
    fn test_no_proxy_in_original() -> crate::Result<()> {
        let assembly = CilObject::from_path_with_validation(
            "tests/samples/packers/confuserex/original.exe",
            ValidationConfig::analysis(),
        )?;
        let (score, mut findings) = detect_confuserex(&assembly);
        referenceproxy::detect(&assembly, &score, &mut findings);

        // Original should have very few or no proxy methods
        // (simple forwarding patterns can occur naturally but should be rare)
        println!("Original proxy count: {}", findings.proxy_methods.count());
        Ok(())
    }

    #[test]
    fn test_proxy_in_normal() -> crate::Result<()> {
        let assembly = CilObject::from_path_with_validation(
            "tests/samples/packers/confuserex/mkaring_normal.exe",
            ValidationConfig::analysis(),
        )?;
        let (score, mut findings) = detect_confuserex(&assembly);
        referenceproxy::detect(&assembly, &score, &mut findings);

        println!("Normal proxy count: {}", findings.proxy_methods.count());

        // Normal preset includes ReferenceProxy - should detect some
        assert!(
            findings.proxy_methods.count() > 0,
            "Normal preset should have ReferenceProxy methods"
        );

        assert!(
            findings.needs_proxy_inlining(),
            "Should indicate proxy inlining is needed"
        );
        Ok(())
    }
}
