//! ConfuserEx Anti-Dump Protection Detection and Neutralization
//!
//! This module provides detection and neutralization for ConfuserEx's anti-dump
//! protection, which corrupts PE headers, metadata directories, section names,
//! and import table entries at runtime to prevent memory dumps.
//!
//! # Source Code Analysis
//!
//! Based on analysis of the ConfuserEx source code at:
//! - `Confuser.Protections/AntiDumpProtection.cs` - Protection entry point
//! - `Confuser.Runtime/AntiDump.cs` - Runtime implementation
//!
//! # Protection Preset
//!
//! Anti-dump is part of the **Maximum** preset:
//! ```csharp
//! // From AntiDumpProtection.cs:
//! public override ProtectionPreset Preset {
//!     get { return ProtectionPreset.Maximum; }
//! }
//! ```
//!
//! # What AntiDump Does at Runtime
//!
//! 1. Gets module base via `Marshal.GetHINSTANCE(typeof(AntiDump).Module)`
//! 2. Parses PE header (offset 0x3c) to find section table and metadata directory
//! 3. Uses `VirtualProtect` to make regions writable
//! 4. Zeros section header names (8 bytes each) via `Marshal.Copy(new byte[8], ...)`
//! 5. Zeros the metadata directory (4 DWORDs)
//! 6. Zeros the metadata header magic and stream names
//! 7. Corrupts import table: renames `mscoree.dll` → `ntldll.dll`,
//!    `_CorExeMain` → `NtContinue`
//!
//! # Detection Signature
//!
//! The key differentiator from AntiTamper is `Marshal.Copy`:
//! - **AntiDump**: `VirtualProtect` + `GetHINSTANCE` + `get_Module` + `Marshal.Copy`
//! - **AntiTamper**: `VirtualProtect` + `GetHINSTANCE` + `get_Module` (no `Marshal.Copy`)
//!
//! Both are injected as `call Initialize` at position 0 in `<Module>::.cctor`.
//!
//! # Injection Point
//!
//! Anti-dump initialization is injected at the beginning of `<Module>::.cctor`:
//! ```csharp
//! // From AntiDumpProtection.cs:
//! cctor.Body.Instructions.Insert(0, Instruction.Create(OpCodes.Call, init));
//! ```
//!
//! # Neutralization Strategy
//!
//! Since AntiDump is purely a runtime protection (it doesn't modify the binary
//! on disk), neutralization involves:
//! 1. **VirtualProtect calls**: Replace with constant false
//! 2. **Marshal.Copy calls**: Replace with no-op
//! 3. **GetHINSTANCE calls**: Replace with constant null
//!
//! After neutralization, the anti-dump method becomes dead code and is removed
//! during cleanup.
//!
//! # Test Samples
//!
//! | Sample | Has Anti-Dump | Notes |
//! |--------|--------------|-------|
//! | `original.exe` | No | Unprotected |
//! | `mkaring_normal.exe` | No | Normal preset (no anti-dump) |
//! | `mkaring_maximum.exe` | Yes | Maximum preset |

use std::{
    collections::HashSet,
    sync::{Arc, OnceLock},
};

use crate::{
    analysis::{ConstValue, SsaFunction, SsaOp, SsaVarId},
    assembly::{opcodes, Operand},
    compiler::{CompilerContext, EventKind, EventLog, SsaPass},
    deobfuscation::{
        detection::{DetectionEvidence, DetectionScore},
        findings::DeobfuscationFindings,
        obfuscators::confuserex::utils,
    },
    metadata::token::Token,
    CilObject, Result,
};

/// Result of anti-dump detection for a single method.
#[derive(Debug, Clone)]
pub struct AntiDumpMethodInfo {
    /// The method token.
    pub token: Token,
    /// Whether this method calls VirtualProtect.
    pub calls_virtualprotect: bool,
    /// Whether this method calls GetHINSTANCE.
    pub calls_gethinstance: bool,
    /// Whether this method calls get_Module.
    pub calls_get_module: bool,
    /// Whether this method calls Marshal.Copy (key differentiator from AntiTamper).
    pub calls_marshal_copy: bool,
}

/// Result of anti-dump detection.
#[derive(Debug, Default)]
pub struct AntiDumpDetectionResult {
    /// Methods detected as anti-dump.
    pub methods: Vec<AntiDumpMethodInfo>,
    /// P/Invoke methods found for anti-dump APIs.
    pub pinvoke_methods: Vec<Token>,
}

impl AntiDumpDetectionResult {
    /// Returns true if any anti-dump protection was detected.
    pub fn is_detected(&self) -> bool {
        !self.methods.is_empty()
    }
}

/// Detects anti-dump protection and returns detailed results.
///
/// This performs comprehensive detection of ConfuserEx anti-dump protection
/// and returns structured results.
pub fn detect_antidump(assembly: &CilObject) -> AntiDumpDetectionResult {
    AntiDumpDetectionResult {
        methods: find_antidump_methods(assembly),
        ..Default::default()
    }
}

/// Adds detection evidence to the score from detailed results.
pub fn add_antidump_evidence(result: &AntiDumpDetectionResult, score: &DetectionScore) {
    if !result.methods.is_empty() {
        let locations: boxcar::Vec<Token> = boxcar::Vec::new();
        for m in &result.methods {
            locations.push(m.token);
        }

        let confidence = (result.methods.len() * 20).min(40);
        score.add(DetectionEvidence::BytecodePattern {
            name: format!("ConfuserEx anti-dump ({} methods)", result.methods.len()),
            locations,
            confidence,
        });
    }
}

/// Finds methods that appear to be anti-dump methods.
///
/// Detection is based on call patterns:
/// - `VirtualProtect` (via P/Invoke import map)
/// - `GetHINSTANCE` (Marshal.GetHINSTANCE)
/// - `get_Module` (typeof(...).Module)
/// - `Copy` (Marshal.Copy — the key differentiator from AntiTamper)
///
/// A method matching all four is an AntiDump method.
fn find_antidump_methods(assembly: &CilObject) -> Vec<AntiDumpMethodInfo> {
    let mut found = Vec::new();

    let import_map = utils::build_pinvoke_import_map(assembly);

    for method in &assembly.query_methods().has_body() {
        let Some(cfg) = method.cfg() else {
            continue;
        };

        let mut calls_virtualprotect = false;
        let mut calls_gethinstance = false;
        let mut calls_get_module = false;
        let mut calls_marshal_copy = false;

        for node_id in cfg.node_ids() {
            let Some(block) = cfg.block(node_id) else {
                continue;
            };

            for instr in &block.instructions {
                if instr.opcode == opcodes::CALL || instr.opcode == opcodes::CALLVIRT {
                    if let Operand::Token(token) = &instr.operand {
                        if let Some(name) =
                            utils::resolve_call_target(assembly, *token, &import_map)
                        {
                            match name.as_str() {
                                "VirtualProtect" => calls_virtualprotect = true,
                                "GetHINSTANCE" => calls_gethinstance = true,
                                "get_Module" => calls_get_module = true,
                                "Copy" => calls_marshal_copy = true,
                                _ => {}
                            }
                        }
                    }
                }
            }
        }

        // AntiDump requires all four: VirtualProtect + GetHINSTANCE + get_Module + Marshal.Copy
        // The Marshal.Copy differentiates it from AntiTamper which has the first three
        // but NOT Marshal.Copy.
        if calls_virtualprotect && calls_gethinstance && calls_get_module && calls_marshal_copy {
            found.push(AntiDumpMethodInfo {
                token: method.token,
                calls_virtualprotect,
                calls_gethinstance,
                calls_get_module,
                calls_marshal_copy,
            });
        }
    }

    found
}

/// Detects anti-dump protection patterns and populates findings.
///
/// This is called by the orchestrator in detection.rs to detect
/// ConfuserEx anti-dump protection.
pub fn detect(assembly: &CilObject, score: &DetectionScore, findings: &mut DeobfuscationFindings) {
    let result = detect_antidump(assembly);

    // Populate findings
    for method_info in &result.methods {
        findings.anti_dump_methods.push(method_info.token);
    }

    // Add detection evidence
    add_antidump_evidence(&result, score);
}

/// Anti-dump neutralization pass for ConfuserEx.
///
/// This pass identifies and neutralizes anti-dump operations in SSA form.
/// It should run during the cleanup phase after SSA normalization.
///
/// The pass also handles `.cctor` cleanup for anti-dump patterns that
/// are injected into the module static constructor.
pub struct ConfuserExAntiDumpPass {
    /// Tokens of anti-dump methods (from detection findings).
    anti_dump_method_tokens: HashSet<Token>,
    /// Whether to also process module .cctor for anti-dump patterns.
    include_module_cctor: bool,
    /// Cached token for the module .cctor (populated on first use).
    module_cctor_token: OnceLock<Option<Token>>,
}

impl Default for ConfuserExAntiDumpPass {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfuserExAntiDumpPass {
    /// Creates a new anti-dump pass.
    #[must_use]
    pub fn new() -> Self {
        Self {
            anti_dump_method_tokens: HashSet::new(),
            include_module_cctor: false,
            module_cctor_token: OnceLock::new(),
        }
    }

    /// Creates a new pass with known anti-dump method tokens.
    ///
    /// These tokens come from the detection phase and help the pass
    /// focus on methods that actually contain anti-dump code.
    #[must_use]
    pub fn with_methods(tokens: impl IntoIterator<Item = Token>) -> Self {
        let tokens: HashSet<_> = tokens.into_iter().collect();
        let include_cctor = !tokens.is_empty();
        Self {
            anti_dump_method_tokens: tokens,
            include_module_cctor: include_cctor,
            module_cctor_token: OnceLock::new(),
        }
    }

    /// Gets the module .cctor token, lazily initializing if needed.
    fn get_module_cctor(&self, assembly: &CilObject) -> Option<Token> {
        *self
            .module_cctor_token
            .get_or_init(|| assembly.types().module_cctor())
    }

    /// Checks if a method call is VirtualProtect.
    fn is_virtualprotect(method_name: &str) -> bool {
        method_name.contains("VirtualProtect")
    }

    /// Checks if a method call is Marshal.Copy.
    fn is_marshal_copy(method_name: &str) -> bool {
        method_name.contains("Marshal") && method_name.contains("Copy")
    }

    /// Checks if a method call is Marshal.GetHINSTANCE.
    fn is_gethinstance(method_name: &str) -> bool {
        method_name.contains("Marshal") && method_name.contains("GetHINSTANCE")
    }

    /// Neutralizes anti-dump operations in a single SSA function.
    fn neutralize_antidump(
        ssa: &mut SsaFunction,
        method_token: Token,
        assembly: &CilObject,
        changeset: &mut EventLog,
    ) {
        for block in ssa.blocks_mut() {
            for instr in block.instructions_mut() {
                match instr.op() {
                    SsaOp::Call { dest, method, .. } | SsaOp::CallVirt { dest, method, .. } => {
                        let method_name = utils::get_type_name_from_token(assembly, method.token())
                            .unwrap_or_else(|| format!("{method}"));
                        let dest = *dest;
                        let method_ref = *method;

                        // Replace VirtualProtect with constant false
                        if Self::is_virtualprotect(&method_name) {
                            if let Some(dest_var) = dest {
                                instr.set_op(SsaOp::Const {
                                    dest: dest_var,
                                    value: ConstValue::from_bool(false),
                                });
                                changeset
                                    .record(EventKind::InstructionRemoved)
                                    .method(method_token)
                                    .message(format!(
                                        "Neutralized VirtualProtect: {method_ref} -> false"
                                    ));
                            }
                        }
                        // Replace Marshal.Copy with no-op
                        else if Self::is_marshal_copy(&method_name) {
                            let dummy_dest = dest.unwrap_or_else(SsaVarId::new);
                            instr.set_op(SsaOp::Const {
                                dest: dummy_dest,
                                value: ConstValue::Null,
                            });
                            changeset
                                .record(EventKind::InstructionRemoved)
                                .method(method_token)
                                .message(format!("Neutralized Marshal.Copy: {method_ref}"));
                        }
                        // Replace GetHINSTANCE with constant null
                        else if Self::is_gethinstance(&method_name) {
                            if let Some(dest_var) = dest {
                                instr.set_op(SsaOp::Const {
                                    dest: dest_var,
                                    value: ConstValue::Null,
                                });
                                changeset
                                    .record(EventKind::InstructionRemoved)
                                    .method(method_token)
                                    .message(format!(
                                        "Neutralized GetHINSTANCE: {method_ref} -> null"
                                    ));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

impl SsaPass for ConfuserExAntiDumpPass {
    fn name(&self) -> &'static str {
        "ConfuserExAntiDump"
    }

    fn should_run(&self, method_token: Token, _ctx: &CompilerContext) -> bool {
        // Run on known anti-dump methods
        if self.anti_dump_method_tokens.contains(&method_token) {
            return true;
        }

        // If we're including module .cctor, we need to run on all methods
        // (we'll filter in run_on_method since we don't have assembly here)
        if self.include_module_cctor {
            return true;
        }

        // If no specific tokens, run on all methods
        self.anti_dump_method_tokens.is_empty()
    }

    fn run_on_method(
        &self,
        ssa: &mut SsaFunction,
        method_token: Token,
        ctx: &CompilerContext,
        assembly: &Arc<CilObject>,
    ) -> Result<bool> {
        // Check if we should process this method
        let is_target_method = self.anti_dump_method_tokens.contains(&method_token);

        // Also check if this is the module .cctor when include_module_cctor is set
        let is_module_cctor = if self.include_module_cctor && !is_target_method {
            let cctor_token = self.get_module_cctor(assembly);
            cctor_token == Some(method_token)
        } else {
            false
        };

        // Skip if not a target method and not the module .cctor
        if !is_target_method && !is_module_cctor && !self.anti_dump_method_tokens.is_empty() {
            return Ok(false);
        }

        let mut changes = EventLog::new();
        Self::neutralize_antidump(ssa, method_token, assembly, &mut changes);

        let changed = !changes.is_empty();
        if changed {
            ctx.events.merge(&changes);
        }
        Ok(changed)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        deobfuscation::obfuscators::confuserex::antidump::detect_antidump, CilObject,
        ValidationConfig,
    };

    const SAMPLES_DIR: &str = "tests/samples/packers/confuserex";

    #[test]
    fn test_original_no_antidump() -> crate::Result<()> {
        let path = format!("{}/original.exe", SAMPLES_DIR);
        let assembly = CilObject::from_path_with_validation(&path, ValidationConfig::analysis())?;

        let result = detect_antidump(&assembly);

        assert!(!result.is_detected(), "Original should have no anti-dump");
        Ok(())
    }

    #[test]
    fn test_normal_no_antidump() -> crate::Result<()> {
        let path = format!("{}/mkaring_normal.exe", SAMPLES_DIR);
        let assembly = CilObject::from_path_with_validation(&path, ValidationConfig::analysis())?;

        let result = detect_antidump(&assembly);

        assert!(
            !result.is_detected(),
            "Normal preset should NOT have anti-dump"
        );
        Ok(())
    }

    #[test]
    fn test_maximum_has_antidump() -> crate::Result<()> {
        let path = format!("{}/mkaring_maximum.exe", SAMPLES_DIR);
        let assembly = CilObject::from_path_with_validation(&path, ValidationConfig::analysis())?;

        let result = detect_antidump(&assembly);

        eprintln!("Anti-dump methods found: {}", result.methods.len());
        for m in &result.methods {
            eprintln!(
                "  0x{:08X}: VirtualProtect={}, GetHINSTANCE={}, get_Module={}, Marshal.Copy={}",
                m.token.value(),
                m.calls_virtualprotect,
                m.calls_gethinstance,
                m.calls_get_module,
                m.calls_marshal_copy,
            );
        }

        assert!(result.is_detected(), "Maximum preset should have anti-dump");

        Ok(())
    }
}
