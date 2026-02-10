//! ConfuserEx Anti-Debug Protection Detection and Neutralization
//!
//! This module provides detection and neutralization for ConfuserEx's anti-debug
//! protection, which prevents debugging and profiling of the protected assembly.
//!
//! # Source Code Analysis
//!
//! Based on analysis of the ConfuserEx source code at:
//! - `Confuser.Protections/AntiDebugProtection.cs` - Protection entry point
//! - `Confuser.Runtime/AntiDebug.Safe.cs` - Safe mode (managed-only)
//! - `Confuser.Runtime/AntiDebug.Win32.cs` - Win32 mode (P/Invoke)
//! - `Confuser.Runtime/AntiDebug.Antinet.cs` - Antinet mode (.NET-specific)
//!
//! # Protection Preset
//!
//! Anti-debug is part of the **Minimum** preset:
//! ```csharp
//! // From AntiDebugProtection.cs line 34:
//! public override ProtectionPreset Preset {
//!     get { return ProtectionPreset.Minimum; }
//! }
//! ```
//!
//! # Protection Modes
//!
//! ## 1. Safe Mode (`AntiMode.Safe`) - Default
//!
//! **Source:** `Confuser.Runtime/AntiDebug.Safe.cs`
//!
//! Uses only managed APIs, making it cross-platform compatible:
//!
//! **Initialization checks:**
//! ```csharp
//! // Check for profiler via environment variable
//! if ("1".Equals(Environment.GetEnvironmentVariable("COR_ENABLE_PROFILING")))
//!     Environment.FailFast(null);
//! ```
//!
//! **Background thread checks (runs every 1 second):**
//! ```csharp
//! while (true) {
//!     if (Debugger.IsAttached || Debugger.IsLogging())
//!         Environment.FailFast(null);
//!     if (!th.IsAlive)  // Anti-tampering of the check thread
//!         Environment.FailFast(null);
//!     Thread.Sleep(1000);
//! }
//! ```
//!
//! **Detection signature:**
//! - Call to `Debugger.IsAttached`
//! - Call to `Debugger.IsLogging`
//! - Call to `Environment.FailFast`
//! - Call to `Environment.GetEnvironmentVariable` with "COR" prefix strings
//! - Background thread with `IsBackground = true`
//!
//! ## 2. Win32 Mode (`AntiMode.Win32`)
//!
//! **Source:** `Confuser.Runtime/AntiDebug.Win32.cs`
//!
//! Uses Windows-specific P/Invoke for stronger detection:
//!
//! **P/Invoke declarations:**
//! ```csharp
//! [DllImport("ntdll.dll")]
//! private static extern int NtQueryInformationProcess(...);
//!
//! [DllImport("kernel32.dll")]
//! static extern bool CloseHandle(IntPtr hObject);
//!
//! [DllImport("kernel32.dll")]
//! static extern bool IsDebuggerPresent();
//!
//! [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
//! static extern int OutputDebugString(string str);
//! ```
//!
//! **Anti-dnSpy check:**
//! ```csharp
//! Process here = GetParentProcess();
//! if (here != null && here.ProcessName.ToLower().Contains("dnspy"))
//!     Environment.FailFast("");
//! ```
//!
//! **Background thread checks:**
//! - `Debugger.IsAttached` and `Debugger.IsLogging()` (managed)
//! - `IsDebuggerPresent()` (native)
//! - `Process.GetCurrentProcess().Handle == IntPtr.Zero` (handle check)
//! - `OutputDebugString("") > IntPtr.Size` (debug output check)
//! - `CloseHandle(IntPtr.Zero)` throws if debugger (exception check)
//!
//! **Detection signature:**
//! - P/Invoke for `IsDebuggerPresent`, `NtQueryInformationProcess`, `CloseHandle`, `OutputDebugString`
//! - Call to `Process.GetCurrentProcess()`
//! - Parent process name check for "dnspy"
//!
//! ## 3. Antinet Mode (`AntiMode.Antinet`)
//!
//! **Source:** `Confuser.Runtime/AntiDebug.Antinet.cs`
//!
//! Uses .NET-specific techniques to detect managed debuggers:
//!
//! ```csharp
//! static void Initialize() {
//!     if (!InitializeAntiDebugger())
//!         Environment.FailFast(null);
//!     InitializeAntiProfiler();
//!     if (IsProfilerAttached) {
//!         Environment.FailFast(null);
//!         PreventActiveProfilerFromReceivingProfilingMessages();
//!     }
//! }
//! ```
//!
//! **Detection signature:**
//! - Methods named `InitializeAntiDebugger`, `InitializeAntiProfiler`
//! - Field named `IsProfilerAttached`
//! - Uses `HandleProcessCorruptedStateExceptionsAttribute`
//!
//! # Injection Point
//!
//! Anti-debug initialization is injected at the beginning of `<Module>::.cctor`:
//! ```csharp
//! // From AntiDebugProtection.cs line 94:
//! cctor.Body.Instructions.Insert(0, Instruction.Create(OpCodes.Call, init));
//! ```
//!
//! # Neutralization Strategy
//!
//! 1. **Debugger checks**: Replace with constant false so the check
//!    always succeeds (debugger appears not attached)
//! 2. **FailFast calls**: Replace with no-op (constant load)
//!    to prevent termination
//!
//! # Limitations
//!
//! - P/Invoke calls to `IsDebuggerPresent` require external resolution
//!   and are not handled in SSA form (handled by detection instead)
//! - Worker threads that continuously check are marked for removal
//!   via dead method elimination
//!
//! # Test Samples
//!
//! | Sample | Has Anti-Debug | Mode | Notes |
//! |--------|----------------|------|-------|
//! | `original.exe` | No | N/A | Unprotected |
//! | `mkaring_minimal.exe` | Yes | Safe | Minimum preset |
//! | `mkaring_normal.exe` | Yes | Safe | Normal preset |
//! | `mkaring_maximum.exe` | Yes | Safe | Maximum preset |

use std::{
    collections::HashSet,
    sync::{Arc, OnceLock},
};

use crate::{
    analysis::{ConstValue, SsaFunction, SsaOp, SsaVarId},
    assembly::Operand,
    compiler::{CompilerContext, EventKind, EventLog, SsaPass},
    deobfuscation::{
        detection::{DetectionEvidence, DetectionScore},
        obfuscators::confuserex::findings::ConfuserExFindings,
    },
    metadata::{tables::TableId, token::Token, typesystem::CilTypeReference},
    CilObject, Result,
};

/// CIL opcode for `call` instruction.
const OPCODE_CALL: u8 = 0x28;
/// CIL opcode for `callvirt` instruction.
const OPCODE_CALLVIRT: u8 = 0x6F;

/// Detected anti-debug mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AntiDebugMode {
    /// Safe mode: managed-only APIs (Debugger.IsAttached, IsLogging, FailFast)
    Safe,

    /// Win32 mode: P/Invoke (IsDebuggerPresent, NtQueryInformationProcess, etc.)
    Win32,

    /// Antinet mode: .NET-specific anti-debug and anti-profiler
    Antinet,

    /// Unknown mode: anti-debug detected but mode couldn't be determined
    Unknown,
}

/// Result of anti-debug detection for a single method.
#[derive(Debug, Clone)]
pub struct AntiDebugMethodInfo {
    /// The method token.
    pub token: Token,
    /// Detected anti-debug mode.
    pub mode: AntiDebugMode,
    /// Calls Debugger.IsAttached
    pub calls_is_attached: bool,
    /// Calls Debugger.IsLogging
    pub calls_is_logging: bool,
    /// Calls Environment.FailFast
    pub calls_failfast: bool,
    /// Calls IsDebuggerPresent (Win32)
    pub calls_is_debugger_present: bool,
    /// Calls NtQueryInformationProcess (Win32)
    pub calls_nt_query: bool,
    /// Calls Process.GetCurrentProcess
    pub calls_get_current_process: bool,
    /// Creates background thread (Thread constructor + IsBackground)
    pub creates_background_thread: bool,
}

/// Result of anti-debug detection.
#[derive(Debug, Default)]
pub struct AntiDebugDetectionResult {
    /// Methods detected as anti-debug.
    pub methods: Vec<AntiDebugMethodInfo>,
    /// Detected mode (most confident).
    pub detected_mode: Option<AntiDebugMode>,
    /// P/Invoke methods found for anti-debug APIs.
    pub pinvoke_methods: Vec<Token>,
}

impl AntiDebugDetectionResult {
    /// Returns true if any anti-debug protection was detected.
    pub fn is_detected(&self) -> bool {
        !self.methods.is_empty()
    }
}

/// Detects anti-debug protection and returns detailed results.
///
/// This performs comprehensive detection of ConfuserEx anti-debug protection
/// and returns structured results with mode information.
pub fn detect_antidebug(assembly: &CilObject) -> AntiDebugDetectionResult {
    let mut result = AntiDebugDetectionResult::default();

    // Detect P/Invoke methods for anti-debug APIs
    result.pinvoke_methods = find_antidebug_pinvokes(assembly);

    // Detect anti-debug methods
    result.methods = find_antidebug_methods(assembly);

    // Determine mode
    result.detected_mode = determine_mode(&result);

    result
}

/// Adds detection evidence to the score from detailed results.
pub fn add_antidebug_evidence(result: &AntiDebugDetectionResult, score: &DetectionScore) {
    if !result.methods.is_empty() {
        let locations: boxcar::Vec<Token> = boxcar::Vec::new();
        for m in &result.methods {
            locations.push(m.token);
        }

        let mode_name = match result.detected_mode {
            Some(AntiDebugMode::Safe) => "Safe",
            Some(AntiDebugMode::Win32) => "Win32",
            Some(AntiDebugMode::Antinet) => "Antinet",
            Some(AntiDebugMode::Unknown) | None => "Unknown",
        };

        let confidence = (result.methods.len() * 20).min(40);
        score.add(DetectionEvidence::BytecodePattern {
            name: format!(
                "ConfuserEx anti-debug ({} mode, {} methods)",
                mode_name,
                result.methods.len()
            ),
            locations,
            confidence,
        });
    }
}

/// Finds P/Invoke methods for anti-debug APIs.
fn find_antidebug_pinvokes(assembly: &CilObject) -> Vec<Token> {
    let antidebug_apis = [
        "IsDebuggerPresent",
        "NtQueryInformationProcess",
        "CloseHandle",
        "OutputDebugString",
        "CheckRemoteDebuggerPresent",
    ];

    let pinvokes = assembly
        .query_methods()
        .native()
        .filter(|m| antidebug_apis.iter().any(|api| m.name == *api))
        .tokens();

    pinvokes
}

/// Finds methods that appear to be anti-debug methods using CFG analysis.
fn find_antidebug_methods(assembly: &CilObject) -> Vec<AntiDebugMethodInfo> {
    let mut found = Vec::new();

    for method in assembly.query_methods().has_body().iter() {
        let Some(cfg) = method.cfg() else {
            continue;
        };

        let mut calls_is_attached = false;
        let mut calls_is_logging = false;
        let mut calls_failfast = false;
        let mut calls_is_debugger_present = false;
        let mut calls_nt_query = false;
        let mut calls_get_current_process = false;
        let mut calls_set_is_background = false;
        let mut calls_thread_ctor = false;

        for node_id in cfg.node_ids() {
            let Some(block) = cfg.block(node_id) else {
                continue;
            };

            for instr in &block.instructions {
                if instr.opcode == OPCODE_CALL || instr.opcode == OPCODE_CALLVIRT {
                    if let Operand::Token(token) = &instr.operand {
                        if let Some(name) = resolve_method_name(assembly, *token) {
                            match name.as_str() {
                                "get_IsAttached" => calls_is_attached = true,
                                "IsLogging" => calls_is_logging = true,
                                "FailFast" => calls_failfast = true,
                                "IsDebuggerPresent" => calls_is_debugger_present = true,
                                "NtQueryInformationProcess" => calls_nt_query = true,
                                "GetCurrentProcess" => calls_get_current_process = true,
                                "set_IsBackground" => calls_set_is_background = true,
                                ".ctor" => {
                                    // Check if it's Thread constructor
                                    if token.is_table(TableId::MemberRef) {
                                        // MemberRef
                                        if let Some(member) = assembly.refs_members().get(token) {
                                            if let CilTypeReference::TypeRef(type_ref) =
                                                &member.value().declaredby
                                            {
                                                if let Some(name) = type_ref.name() {
                                                    if name.contains("Thread") {
                                                        calls_thread_ctor = true;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }

        let creates_background_thread = calls_thread_ctor && calls_set_is_background;

        // Determine if this looks like an anti-debug method
        let is_safe_mode = (calls_is_attached || calls_is_logging) && calls_failfast;
        let is_win32_mode = calls_is_debugger_present || calls_nt_query;
        let has_any_indicator =
            is_safe_mode || is_win32_mode || (calls_failfast && creates_background_thread);

        if has_any_indicator {
            let mode = if is_win32_mode {
                AntiDebugMode::Win32
            } else if is_safe_mode {
                AntiDebugMode::Safe
            } else {
                AntiDebugMode::Unknown
            };

            found.push(AntiDebugMethodInfo {
                token: method.token,
                mode,
                calls_is_attached,
                calls_is_logging,
                calls_failfast,
                calls_is_debugger_present,
                calls_nt_query,
                calls_get_current_process,
                creates_background_thread,
            });
        }
    }

    found
}

/// Resolves a call target token to a method name.
fn resolve_method_name(assembly: &CilObject, token: Token) -> Option<String> {
    match token.table() {
        0x06 => Some(assembly.methods().get(&token)?.value().name.clone()),
        0x0A => Some(assembly.refs_members().get(&token)?.value().name.clone()),
        _ => None,
    }
}

/// Determines the most likely anti-debug mode.
fn determine_mode(result: &AntiDebugDetectionResult) -> Option<AntiDebugMode> {
    if result.methods.is_empty() {
        return None;
    }

    // Win32 mode has the strongest indicators
    if result
        .methods
        .iter()
        .any(|m| m.mode == AntiDebugMode::Win32)
        || !result.pinvoke_methods.is_empty()
    {
        return Some(AntiDebugMode::Win32);
    }

    // Safe mode is the default
    if result.methods.iter().any(|m| m.mode == AntiDebugMode::Safe) {
        return Some(AntiDebugMode::Safe);
    }

    Some(AntiDebugMode::Unknown)
}

/// Detects anti-debug protection patterns and populates findings.
///
/// This is called by the orchestrator in detection.rs to detect
/// ConfuserEx anti-debug protection.
pub fn detect(assembly: &CilObject, score: &DetectionScore, findings: &mut ConfuserExFindings) {
    let result = detect_antidebug(assembly);

    // Populate findings
    for method_info in &result.methods {
        findings.anti_debug_methods.push(method_info.token);
    }

    // Add detection evidence
    add_antidebug_evidence(&result, score);
}

/// Helper function to get the full type name from a call operand token.
/// Used by the SSA pass for pattern matching.
fn get_type_name_from_token(assembly: &CilObject, token: Token) -> Option<String> {
    if let Some(cil_type) = assembly.types().get(&token) {
        return Some(cil_type.fullname());
    }

    // Try MemberRef lookup (for method/field references)
    if let Some(member_ref_entry) = assembly.refs_members().get(&token) {
        let member_ref = member_ref_entry.value();

        // Extract the declaring type from the MemberRef
        if let Some(type_name) = member_ref.declaredby.fullname() {
            return Some(format!("{}::{}", type_name, member_ref.name));
        }
    }

    None
}

/// Anti-debug neutralization pass for ConfuserEx.
///
/// This pass identifies and neutralizes anti-debug checks in SSA form.
/// It should run during the cleanup phase after SSA normalization.
///
/// The pass also handles `.cctor` cleanup for anti-debug patterns that
/// are injected into the module static constructor.
pub struct ConfuserExAntiDebugPass {
    /// Tokens of anti-debug methods (from detection findings).
    anti_debug_method_tokens: HashSet<Token>,
    /// Whether to also process module .cctor for anti-debug patterns.
    include_module_cctor: bool,
    /// Cached token for the module .cctor (populated on first use).
    module_cctor_token: OnceLock<Option<Token>>,
}

impl Default for ConfuserExAntiDebugPass {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfuserExAntiDebugPass {
    /// Creates a new anti-debug pass.
    #[must_use]
    pub fn new() -> Self {
        Self {
            anti_debug_method_tokens: HashSet::new(),
            include_module_cctor: false,
            module_cctor_token: OnceLock::new(),
        }
    }

    /// Creates a new pass with known anti-debug method tokens.
    ///
    /// These tokens come from the detection phase and help the pass
    /// focus on methods that actually contain anti-debug code.
    #[must_use]
    pub fn with_methods(tokens: impl IntoIterator<Item = Token>) -> Self {
        let tokens: HashSet<_> = tokens.into_iter().collect();
        let include_cctor = !tokens.is_empty(); // Include .cctor if any anti-debug detected
        Self {
            anti_debug_method_tokens: tokens,
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

    /// Checks if a method call is a debugger check.
    fn is_debugger_check(&self, method_name: &str) -> bool {
        method_name.contains("Debugger")
            && (method_name.contains("IsAttached") || method_name.contains("IsLogging"))
    }

    /// Checks if a method call is Environment.FailFast.
    fn is_fail_fast(&self, method_name: &str) -> bool {
        method_name.contains("Environment") && method_name.contains("FailFast")
    }

    /// Checks if a method call is Environment.GetEnvironmentVariable.
    fn is_env_var_check(&self, method_name: &str) -> bool {
        method_name.contains("Environment") && method_name.contains("GetEnvironmentVariable")
    }

    /// Checks if a method call is Type.GetMethod (reflection pattern used in anti-debug).
    fn is_reflection_get_method(&self, method_name: &str) -> bool {
        method_name.contains("Type") && method_name.contains("GetMethod")
    }

    /// Checks if a method call is MethodBase.Invoke (reflection pattern used in anti-debug).
    fn is_reflection_invoke(&self, method_name: &str) -> bool {
        (method_name.contains("MethodBase") || method_name.contains("MethodInfo"))
            && method_name.contains("Invoke")
    }

    /// Neutralizes anti-debug operations in a single SSA function.
    fn neutralize_antidebug(
        &self,
        ssa: &mut SsaFunction,
        method_token: Token,
        assembly: &CilObject,
        changeset: &mut EventLog,
    ) {
        for block in ssa.blocks_mut() {
            for instr in block.instructions_mut() {
                match instr.op() {
                    // Check for Call operations
                    SsaOp::Call { dest, method, .. } | SsaOp::CallVirt { dest, method, .. } => {
                        // Resolve method token to full name for pattern matching
                        let method_name = get_type_name_from_token(assembly, method.token())
                            .unwrap_or_else(|| format!("{}", method));
                        let dest = *dest;
                        let method_ref = *method;

                        // Replace debugger checks with constant false
                        if self.is_debugger_check(&method_name) {
                            if let Some(dest_var) = dest {
                                // Replace with: dest = const false
                                instr.set_op(SsaOp::Const {
                                    dest: dest_var,
                                    value: ConstValue::from_bool(false),
                                });
                                changeset
                                    .record(EventKind::InstructionRemoved)
                                    .method(method_token)
                                    .message(format!(
                                        "Neutralized debugger check: {} -> false",
                                        method_ref
                                    ));
                            }
                        }
                        // Replace FailFast with no-op (load null)
                        else if self.is_fail_fast(&method_name) {
                            // For FailFast, we need to replace it with something harmless.
                            // Use a dummy variable if no dest, otherwise use the existing dest.
                            let dummy_dest = dest.unwrap_or_else(SsaVarId::new);
                            instr.set_op(SsaOp::Const {
                                dest: dummy_dest,
                                value: ConstValue::Null,
                            });
                            changeset
                                .record(EventKind::InstructionRemoved)
                                .method(method_token)
                                .message(format!("Neutralized FailFast call: {}", method_ref));
                        }
                        // Replace Environment.GetEnvironmentVariable with null
                        // This neutralizes COR_ENABLE_PROFILING checks
                        else if self.is_env_var_check(&method_name) {
                            if let Some(dest_var) = dest {
                                instr.set_op(SsaOp::Const {
                                    dest: dest_var,
                                    value: ConstValue::Null,
                                });
                                changeset
                                    .record(EventKind::InstructionRemoved)
                                    .method(method_token)
                                    .message(format!(
                                        "Neutralized environment variable check: {} -> null",
                                        method_ref
                                    ));
                            }
                        }
                        // Replace reflection GetMethod with null to break reflection-based checks
                        else if self.is_reflection_get_method(&method_name) {
                            if let Some(dest_var) = dest {
                                instr.set_op(SsaOp::Const {
                                    dest: dest_var,
                                    value: ConstValue::Null,
                                });
                                changeset
                                    .record(EventKind::InstructionRemoved)
                                    .method(method_token)
                                    .message(format!(
                                        "Neutralized reflection GetMethod: {} -> null",
                                        method_ref
                                    ));
                            }
                        }
                        // Replace reflection Invoke with null to break reflection-based execution
                        else if self.is_reflection_invoke(&method_name) {
                            let dummy_dest = dest.unwrap_or_else(SsaVarId::new);
                            instr.set_op(SsaOp::Const {
                                dest: dummy_dest,
                                value: ConstValue::Null,
                            });
                            changeset
                                .record(EventKind::InstructionRemoved)
                                .method(method_token)
                                .message(format!("Neutralized reflection Invoke: {}", method_ref));
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

impl SsaPass for ConfuserExAntiDebugPass {
    fn name(&self) -> &'static str {
        "ConfuserExAntiDebug"
    }

    fn should_run(&self, method_token: Token, _ctx: &CompilerContext) -> bool {
        // Run on known anti-debug methods
        if self.anti_debug_method_tokens.contains(&method_token) {
            return true;
        }

        // If we're including module .cctor, we need to run on all methods
        // (we'll filter in run_on_method since we don't have assembly here)
        if self.include_module_cctor {
            return true;
        }

        // If no specific tokens, run on all methods
        self.anti_debug_method_tokens.is_empty()
    }

    fn run_on_method(
        &self,
        ssa: &mut SsaFunction,
        method_token: Token,
        ctx: &CompilerContext,
        assembly: &Arc<CilObject>,
    ) -> Result<bool> {
        // Check if we should process this method
        let is_target_method = self.anti_debug_method_tokens.contains(&method_token);

        // Also check if this is the module .cctor when include_module_cctor is set
        let is_module_cctor = if self.include_module_cctor && !is_target_method {
            // Use OnceLock to lazily find and cache the .cctor token
            let cctor_token = self.get_module_cctor(assembly);
            cctor_token == Some(method_token)
        } else {
            false
        };

        // Skip if not a target method and not the module .cctor
        if !is_target_method && !is_module_cctor && !self.anti_debug_method_tokens.is_empty() {
            return Ok(false);
        }

        let mut changes = EventLog::new();
        self.neutralize_antidebug(ssa, method_token, assembly, &mut changes);

        let changed = !changes.is_empty();
        if changed {
            ctx.events.merge(changes);
        }
        Ok(changed)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        deobfuscation::obfuscators::confuserex::antidebug::{
            detect_antidebug, ConfuserExAntiDebugPass,
        },
        CilObject, ValidationConfig,
    };

    const SAMPLES_DIR: &str = "tests/samples/packers/confuserex";

    #[test]
    fn test_is_debugger_check() {
        let pass = ConfuserExAntiDebugPass::new();

        assert!(pass.is_debugger_check("System.Diagnostics.Debugger::get_IsAttached"));
        assert!(pass.is_debugger_check("System.Diagnostics.Debugger::IsLogging"));
        assert!(!pass.is_debugger_check("System.Console::WriteLine"));
    }

    #[test]
    fn test_is_fail_fast() {
        let pass = ConfuserExAntiDebugPass::new();

        assert!(pass.is_fail_fast("System.Environment::FailFast"));
        assert!(!pass.is_fail_fast("System.Environment::Exit"));
    }

    #[test]
    fn test_original_no_antidebug() -> crate::Result<()> {
        let path = format!("{}/original.exe", SAMPLES_DIR);
        let assembly = CilObject::from_path_with_validation(&path, ValidationConfig::analysis())?;

        let result = detect_antidebug(&assembly);

        assert!(!result.is_detected(), "Original should have no anti-debug");
        Ok(())
    }

    #[test]
    fn test_normal_has_antidebug() -> crate::Result<()> {
        let path = format!("{}/mkaring_normal.exe", SAMPLES_DIR);
        let assembly = CilObject::from_path_with_validation(&path, ValidationConfig::analysis())?;

        let result = detect_antidebug(&assembly);

        eprintln!("Anti-debug methods found: {}", result.methods.len());
        for m in &result.methods {
            eprintln!(
                "  0x{:08X}: mode={:?}, IsAttached={}, IsLogging={}, FailFast={}, BGThread={}",
                m.token.value(),
                m.mode,
                m.calls_is_attached,
                m.calls_is_logging,
                m.calls_failfast,
                m.creates_background_thread
            );
        }
        eprintln!("Detected mode: {:?}", result.detected_mode);

        assert!(result.is_detected(), "Normal preset should have anti-debug");

        Ok(())
    }
}
