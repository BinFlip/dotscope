//! ConfuserEx Anti-Tamper Protection Detection and Decryption
//!
//! This module provides detection and decryption for ConfuserEx's anti-tamper protection,
//! which encrypts method bodies to prevent tampering and static analysis.
//!
//! # Source Code Analysis
//!
//! Based on analysis of the ConfuserEx source code at:
//! - `Confuser.Protections/AntiTamper/AntiTamperProtection.cs` - Main protection entry point
//! - `Confuser.Runtime/AntiTamper.Normal.cs` - Normal mode runtime
//! - `Confuser.Runtime/AntiTamper.Anti.cs` - Anti mode runtime (with anti-debug)
//! - `Confuser.Runtime/AntiTamper.JIT.cs` - JIT mode runtime (hooks the JIT compiler)
//!
//! # Protection Modes
//!
//! ConfuserEx anti-tamper has three modes, selectable via the `mode` parameter:
//!
//! ## 1. Normal Mode (`Mode.Normal`)
//!
//! **Source:** `Confuser.Runtime/AntiTamper.Normal.cs` and `Confuser.Protections/AntiTamper/NormalMode.cs`
//!
//! **How it works:**
//! 1. Creates a custom PE section with obfuscated name (random `name1 * name2`)
//! 2. Moves **both** method bodies AND the Constants chunk to this section during compilation
//! 3. Encrypts the **entire** section contents using XOR with a derived key
//! 4. At runtime, decrypts the section in-place using `VirtualProtect` to make it writable
//!
//! **What gets encrypted (from NormalMode.cs `CreateSections()`):**
//! ```csharp
//! // Move Constants to encrypted section - includes FieldRVA data!
//! alignment = writer.TextSection.Remove(writer.Constants).Value;
//! newSection.Add(writer.Constants, alignment);
//!
//! // Move encrypted methods
//! var encryptedChunk = new MethodBodyChunks(writer.TheOptions.ShareMethodBodies);
//! newSection.Add(encryptedChunk, 4);
//! foreach (MethodDef method in methods) {
//!     if (!method.HasBody) continue;
//!     MethodBody body = writer.Metadata.GetMethodBody(method);
//!     writer.MethodBodies.Remove(body);
//!     encryptedChunk.Add(body);
//! }
//! ```
//!
//! **IMPORTANT:** The Constants section contains FieldRVA initialization data. When combined
//! with Constants protection (which stores encrypted data in a static field), the LZMA-compressed
//! constants data is also encrypted by anti-tamper. This requires decrypting **both** method
//! bodies AND FieldRVA data during deobfuscation.
//!
//! **Runtime signature:**
//! ```csharp
//! [DllImport("kernel32.dll")]
//! static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
//!
//! static unsafe void Initialize() {
//!     Module m = typeof(AntiTamperNormal).Module;
//!     var b = (byte*)Marshal.GetHINSTANCE(m);
//!     // ... PE parsing to find encrypted section ...
//!     VirtualProtect((IntPtr)e, l << 2, 0x40, out w);  // PAGE_EXECUTE_READWRITE
//!     // ... XOR decryption loop ...
//! }
//! ```
//!
//! **Detection criteria:**
//! - P/Invoke declaration for `VirtualProtect` from `kernel32.dll`
//! - Call to `Marshal.GetHINSTANCE(Module)`
//! - Call to `typeof(...).Module` or `get_Module` property
//! - Methods with encrypted bodies (RVA set but body unparseable)
//!
//! ## 2. Anti Mode (`Mode.Anti`)
//!
//! **Source:** `Confuser.Runtime/AntiTamper.Anti.cs`
//!
//! **How it works:**
//! Same as Normal mode, but with integrated anti-debug checks. The decryption
//! code is interleaved with debugger detection that calls `Environment.FailFast`
//! if a debugger is detected.
//!
//! **Runtime signature:**
//! ```csharp
//! [DllImport("kernel32.dll")]
//! static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
//!
//! [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
//! static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);
//!
//! static unsafe void Initialize() {
//!     // ... same PE parsing ...
//!     CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref isDebuggerPresent);
//!     if (isDebuggerPresent) Environment.FailFast(null);
//!     // ... more checks interspersed with decryption ...
//! }
//! ```
//!
//! **Detection criteria (in addition to Normal mode):**
//! - P/Invoke declaration for `CheckRemoteDebuggerPresent`
//! - Calls to `Process.GetCurrentProcess()`
//! - Calls to `Environment.FailFast`
//!
//! ## 3. JIT Mode (`Mode.JIT`)
//!
//! **Source:** `Confuser.Runtime/AntiTamper.JIT.cs`
//!
//! **How it works:**
//! Instead of decrypting at startup, this mode hooks the CLR's JIT compiler.
//! Method bodies remain encrypted until the moment they are JIT-compiled,
//! at which point they are decrypted on-demand.
//!
//! **Runtime signature:**
//! ```csharp
//! [DllImport("kernel32.dll")]
//! static extern IntPtr LoadLibrary(string lib);
//!
//! [DllImport("kernel32.dll")]
//! static extern IntPtr GetProcAddress(IntPtr lib, string proc);
//!
//! [DllImport("kernel32.dll")]
//! static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
//!
//! static void Hook() {
//!     IntPtr jit = LoadLibrary("clrjit.dll");  // or mscorjit.dll for older .NET
//!     var get = Marshal.GetDelegateForFunctionPointer(GetProcAddress(jit, "getJit"), typeof(getJit));
//!     // ... hooks the JIT compiler's compileMethod function ...
//! }
//! ```
//!
//! **Detection criteria:**
//! - P/Invoke declarations for `LoadLibrary` and `GetProcAddress`
//! - References to JIT-related strings ("clrjit.dll", "mscorjit.dll", "getJit")
//! - Complex hooking structures (delegate types, unsafe code patterns)
//!
//! # Injection Point
//!
//! For all modes, the anti-tamper initialization is injected at the **very beginning**
//! of `<Module>::.cctor` (the module's static constructor):
//!
//! ```csharp
//! // From NormalMode.cs line 92:
//! MethodDef cctor = context.CurrentModule.GlobalType.FindStaticConstructor();
//! cctor.Body.Instructions.Insert(0, Instruction.Create(OpCodes.Call, initMethod));
//! ```
//!
//! # Protection Preset
//!
//! Anti-tamper is part of the **Maximum** preset only:
//! ```csharp
//! // From AntiTamperProtection.cs line 37:
//! public override ProtectionPreset Preset {
//!     get { return ProtectionPreset.Maximum; }
//! }
//! ```
//!
//! # Decryption Strategy
//!
//! This module provides generic anti-tamper decryption by:
//! 1. Loading the PE file into emulator memory at `ImageBase`
//! 2. Leveraging BCL stubs (GetHINSTANCE, VirtualProtect, etc.) from the emulation runtime
//! 3. Emulating the anti-tamper initialization code which decrypts the section in-place
//! 4. Extracting decrypted method bodies from the virtual image
//! 5. Extracting decrypted FieldRVA data from the virtual image (Constants section)
//! 6. Rebuilding the assembly with decrypted data in the standard .text section
//!
//! This approach is fully generic - we don't hardcode encryption keys or algorithms.
//! Instead, we let the obfuscator's own decryption code do the work.
//!
//! **Why FieldRVA extraction is critical:**
//! When Constants protection is combined with Anti-Tamper, the LZMA-compressed
//! constant data (stored at a FieldRVA) is encrypted. Without extracting the
//! decrypted FieldRVA data, the Constants warmup phase receives encrypted data
//! instead of LZMA data, causing the LZMA hook to fail and the deobfuscation
//! to produce incorrect results or crash.
//!
//! # Test Samples
//!
//! | Sample | Has Anti-Tamper | Mode | Notes |
//! |--------|-----------------|------|-------|
//! | `original.exe` | No | N/A | Unprotected baseline |
//! | `mkaring_minimal.exe` | No | N/A | Minimal preset |
//! | `mkaring_normal.exe` | No | N/A | Normal preset (no anti-tamper) |
//! | `mkaring_maximum.exe` | Yes | Unknown | Maximum preset |

use std::{collections::HashMap, sync::Arc};

use crate::{
    assembly::Operand,
    cilassembly::{CilAssembly, GeneratorConfig},
    deobfuscation::{
        changes::{EventKind, EventLog},
        detection::{DetectionEvidence, DetectionScore},
        obfuscators::confuserex::{
            candidates::{find_candidates, ProtectionType},
            findings::ConfuserExFindings,
        },
    },
    emulation::{EmulationOutcome, ProcessBuilder, TracingConfig},
    error::Error,
    metadata::{
        imports::ImportType,
        method::{MethodBody, MethodImplCodeType},
        signatures::{parse_field_signature, TypeSignature},
        tables::{ClassLayoutRaw, FieldRaw, FieldRvaRaw, MethodDefRaw, TableDataOwned, TableId},
        token::Token,
        validation::ValidationConfig,
    },
    CilObject, Result,
};

/// CIL opcode for `call` instruction.
const OPCODE_CALL: u8 = 0x28;
/// CIL opcode for `callvirt` instruction.
const OPCODE_CALLVIRT: u8 = 0x6F;

/// Detected anti-tamper mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AntiTamperMode {
    /// Normal mode: VirtualProtect-based decryption at startup.
    /// P/Invoke: VirtualProtect
    /// Signature: GetHINSTANCE + get_Module + VirtualProtect
    Normal,

    /// Anti mode: Normal + integrated anti-debug checks.
    /// P/Invoke: VirtualProtect, CheckRemoteDebuggerPresent
    /// Signature: Normal + CheckRemoteDebuggerPresent + FailFast
    Anti,

    /// JIT mode: Hooks the JIT compiler for on-demand decryption.
    /// P/Invoke: LoadLibrary, GetProcAddress, VirtualProtect
    /// Signature: LoadLibrary("clrjit.dll") + GetProcAddress("getJit")
    Jit,

    /// Unknown mode: Has encrypted methods but mode couldn't be determined.
    Unknown,
}

/// Result of anti-tamper detection for a single method.
#[derive(Debug, Clone)]
pub struct AntiTamperMethodInfo {
    /// The method token.
    pub token: Token,
    /// Detected anti-tamper mode (if determinable).
    pub mode: AntiTamperMode,
    /// Whether this method calls VirtualProtect.
    pub calls_virtualprotect: bool,
    /// Whether this method calls GetHINSTANCE.
    pub calls_gethinstance: bool,
    /// Whether this method calls get_Module.
    pub calls_get_module: bool,
    /// Whether this method calls CheckRemoteDebuggerPresent.
    pub calls_check_debugger: bool,
    /// Whether this method calls LoadLibrary.
    pub calls_loadlibrary: bool,
    /// Whether this method calls GetProcAddress.
    pub calls_getprocaddress: bool,
    /// Whether this method calls Environment.FailFast.
    pub calls_failfast: bool,
}

/// Result of anti-tamper detection.
#[derive(Debug, Default)]
pub struct AntiTamperDetectionResult {
    /// Methods detected as anti-tamper initialization.
    pub methods: Vec<AntiTamperMethodInfo>,
    /// Count of methods with encrypted bodies.
    pub encrypted_method_count: usize,
    /// Detected anti-tamper mode (most confident).
    pub detected_mode: Option<AntiTamperMode>,
    /// P/Invoke methods found (VirtualProtect, LoadLibrary, etc.)
    pub pinvoke_methods: Vec<Token>,
}

impl AntiTamperDetectionResult {
    /// Returns true if any anti-tamper protection was detected.
    pub fn is_detected(&self) -> bool {
        !self.methods.is_empty() || self.encrypted_method_count > 0
    }

    /// Returns the token of the best anti-tamper initialization method.
    ///
    /// Prefers methods that are NOT the module .cctor, as the .cctor just
    /// calls the actual initialization method.
    pub fn best_init_method(&self) -> Option<Token> {
        // First, try to find a non-.cctor method with strong indicators
        self.methods
            .iter()
            .filter(|m| {
                // Strong indicators: has at least 2 of the key calls
                let indicators = [
                    m.calls_virtualprotect,
                    m.calls_gethinstance,
                    m.calls_get_module,
                    m.calls_loadlibrary && m.calls_getprocaddress,
                ]
                .iter()
                .filter(|&&x| x)
                .count();
                indicators >= 2
            })
            .map(|m| m.token)
            .next()
            .or_else(|| self.methods.first().map(|m| m.token))
    }
}

/// Detects anti-tamper protection and populates findings.
///
/// This is the main detection entry point called by the orchestrator.
/// It detects:
/// - Anti-tamper initialization methods (VirtualProtect + GetHINSTANCE calls)
/// - Encrypted method bodies (methods with RVA but no parseable body)
/// - The specific anti-tamper mode being used
pub fn detect(assembly: &CilObject, score: &DetectionScore, findings: &mut ConfuserExFindings) {
    let result = detect_antitamper(assembly);

    // Populate findings
    for method_info in &result.methods {
        findings.anti_tamper_methods.push(method_info.token);
    }
    findings.encrypted_method_count = result.encrypted_method_count;

    // Add detection evidence
    add_evidence(&result, score);
}

/// Detects anti-tamper protection in an assembly and returns detailed results.
///
/// This function scans for all three anti-tamper modes and identifies:
/// - Anti-tamper initialization methods
/// - The specific mode being used
/// - Encrypted method bodies
pub fn detect_antitamper(assembly: &CilObject) -> AntiTamperDetectionResult {
    let mut result = AntiTamperDetectionResult::default();

    // Detect encrypted method bodies
    result.encrypted_method_count = find_encrypted_methods(assembly).len();

    // Detect P/Invoke methods for anti-tamper APIs
    result.pinvoke_methods = find_antitamper_pinvokes(assembly);

    // Detect anti-tamper initialization methods
    result.methods = find_antitamper_methods(assembly);

    // Determine the mode based on findings
    result.detected_mode = determine_mode(&result);

    result
}

/// Adds detection evidence to the score based on anti-tamper findings.
fn add_evidence(result: &AntiTamperDetectionResult, score: &DetectionScore) {
    // Add evidence for anti-tamper methods
    if !result.methods.is_empty() {
        let locations: boxcar::Vec<Token> = boxcar::Vec::new();
        for m in &result.methods {
            locations.push(m.token);
        }

        let mode_name = match result.detected_mode {
            Some(AntiTamperMode::Normal) => "Normal",
            Some(AntiTamperMode::Anti) => "Anti",
            Some(AntiTamperMode::Jit) => "JIT",
            Some(AntiTamperMode::Unknown) | None => "Unknown",
        };

        let confidence = (result.methods.len() * 25).min(50);
        score.add(DetectionEvidence::BytecodePattern {
            name: format!(
                "ConfuserEx anti-tamper ({} mode, {} methods)",
                mode_name,
                result.methods.len()
            ),
            locations,
            confidence,
        });
    }

    // Add evidence for encrypted method bodies
    if result.encrypted_method_count > 0 {
        let confidence = result.encrypted_method_count.min(50);
        score.add(DetectionEvidence::EncryptedMethodBodies {
            count: result.encrypted_method_count,
            confidence,
        });
    }

    // Add evidence for P/Invoke methods
    if !result.pinvoke_methods.is_empty() {
        let locations: boxcar::Vec<Token> = boxcar::Vec::new();
        for t in &result.pinvoke_methods {
            locations.push(*t);
        }

        score.add(DetectionEvidence::BytecodePattern {
            name: format!(
                "Anti-tamper P/Invoke methods ({} native calls)",
                result.pinvoke_methods.len()
            ),
            locations,
            confidence: 20,
        });
    }
}

/// Finds methods with encrypted bodies in the assembly.
///
/// These are methods where the RVA is set but the body couldn't be parsed,
/// indicating the method body is encrypted.
pub fn find_encrypted_methods(assembly: &CilObject) -> Vec<Token> {
    assembly
        .methods()
        .iter()
        .filter_map(|entry| {
            let method = entry.value();
            if method.rva.is_some_and(|rva| rva > 0) && method.body.get().is_none() {
                Some(method.token)
            } else {
                None
            }
        })
        .collect()
}

/// Builds a map from MethodDef token to P/Invoke import name.
///
/// This is necessary because ConfuserEx renames P/Invoke methods while keeping
/// the actual import name (in the ImplMap table) intact. For example, a method
/// named "VirtualProtect" might be renamed to invisible Unicode characters,
/// but the ImplMap entry still records "VirtualProtect" as the import name.
///
/// Returns a map from MethodDef token to the actual import name.
fn build_pinvoke_import_map(assembly: &CilObject) -> HashMap<Token, String> {
    let mut map = HashMap::new();

    // Iterate over all P/Invoke imports in the imports container
    for import_entry in assembly.imports().cil().iter() {
        let import = import_entry.value();

        // Only process method imports (P/Invoke)
        if let ImportType::Method(method) = &import.import {
            // The import.name is the actual import name from ImplMap (e.g., "VirtualProtect")
            // The method.token is the MethodDef token
            map.insert(method.token, import.name.clone());
        }
    }

    map
}

/// Finds P/Invoke methods that are characteristic of anti-tamper protection.
///
/// Looks for:
/// - VirtualProtect (all modes)
/// - CheckRemoteDebuggerPresent (Anti mode)
/// - LoadLibrary, GetProcAddress (JIT mode)
///
/// Uses the actual import names from the ImplMap table, not the potentially
/// obfuscated method names.
fn find_antitamper_pinvokes(assembly: &CilObject) -> Vec<Token> {
    let mut pinvokes = Vec::new();

    let antitamper_apis = [
        "VirtualProtect",
        "CheckRemoteDebuggerPresent",
        "LoadLibrary",
        "LoadLibraryA",
        "LoadLibraryW",
        "GetProcAddress",
    ];

    // Build a map from MethodDef token to import name
    let import_map = build_pinvoke_import_map(assembly);

    for entry in assembly.methods().iter() {
        let method = entry.value();

        // Check if it's a P/Invoke method
        if !method.impl_code_type.contains(MethodImplCodeType::NATIVE) {
            continue;
        }

        // Look up the actual import name (not the potentially obfuscated method name)
        let import_name = import_map.get(&method.token).map(String::as_str);

        // Check if the import name matches any anti-tamper API
        if let Some(name) = import_name {
            if antitamper_apis.contains(&name) {
                pinvokes.push(method.token);
            }
        }
    }

    pinvokes
}

/// Finds methods that appear to be anti-tamper initialization methods.
///
/// Detection is based on call patterns characteristic of each mode.
/// Uses the actual import names from ImplMap for P/Invoke methods,
/// not the potentially obfuscated method names.
fn find_antitamper_methods(assembly: &CilObject) -> Vec<AntiTamperMethodInfo> {
    let mut found = Vec::new();

    // Build import map once for all method analysis
    let import_map = build_pinvoke_import_map(assembly);

    for entry in assembly.methods().iter() {
        let method = entry.value();

        let Some(_body) = method.body.get() else {
            continue;
        };

        let Some(cfg) = method.cfg() else {
            continue;
        };

        // Track what this method calls
        let mut calls_virtualprotect = false;
        let mut calls_gethinstance = false;
        let mut calls_get_module = false;
        let mut calls_check_debugger = false;
        let mut calls_loadlibrary = false;
        let mut calls_getprocaddress = false;
        let mut calls_failfast = false;

        for node_id in cfg.node_ids() {
            let Some(block) = cfg.block(node_id) else {
                continue;
            };

            for instr in &block.instructions {
                if instr.opcode == OPCODE_CALL || instr.opcode == OPCODE_CALLVIRT {
                    if let Operand::Token(token) = &instr.operand {
                        if let Some(name) = resolve_call_target(assembly, *token, &import_map) {
                            match name.as_str() {
                                "VirtualProtect" => calls_virtualprotect = true,
                                "GetHINSTANCE" => calls_gethinstance = true,
                                "get_Module" => calls_get_module = true,
                                "CheckRemoteDebuggerPresent" => calls_check_debugger = true,
                                "LoadLibrary" | "LoadLibraryA" | "LoadLibraryW" => {
                                    calls_loadlibrary = true
                                }
                                "GetProcAddress" => calls_getprocaddress = true,
                                "FailFast" => calls_failfast = true,
                                _ => {}
                            }
                        }
                    }
                }
            }
        }

        // Determine if this looks like an anti-tamper method
        // Normal mode: GetHINSTANCE + get_Module + VirtualProtect
        // Anti mode: Normal + CheckRemoteDebuggerPresent
        // JIT mode: LoadLibrary + GetProcAddress (+ VirtualProtect typically)
        //
        // IMPORTANT: Constants protection also uses GetHINSTANCE + get_Module to read
        // encrypted data from the PE, but it does NOT call VirtualProtect (no need to
        // modify memory protection for reading). The key differentiator is VirtualProtect.

        let is_normal_mode = calls_gethinstance && calls_get_module && calls_virtualprotect;
        let is_anti_mode = is_normal_mode && calls_check_debugger;
        let is_jit_mode = calls_loadlibrary && calls_getprocaddress && calls_virtualprotect;

        if is_normal_mode || is_anti_mode || is_jit_mode {
            // All modes require VirtualProtect, so we can determine mode precisely
            let mode = if is_jit_mode {
                AntiTamperMode::Jit
            } else if is_anti_mode {
                AntiTamperMode::Anti
            } else {
                AntiTamperMode::Normal
            };

            found.push(AntiTamperMethodInfo {
                token: method.token,
                mode,
                calls_virtualprotect,
                calls_gethinstance,
                calls_get_module,
                calls_check_debugger,
                calls_loadlibrary,
                calls_getprocaddress,
                calls_failfast,
            });
        }
    }

    found
}

/// Resolves a call target token to a method name.
///
/// For MethodDef tokens that are P/Invoke methods, returns the actual import name
/// from the ImplMap table (not the potentially obfuscated method name).
/// For MemberRef tokens (external calls), returns the member reference name.
fn resolve_call_target(
    assembly: &CilObject,
    token: Token,
    import_map: &HashMap<Token, String>,
) -> Option<String> {
    match token.table() {
        // MethodDef - check if it's a P/Invoke with a real import name
        0x06 => {
            // First, check if this is a P/Invoke method with a known import name
            if let Some(import_name) = import_map.get(&token) {
                return Some(import_name.clone());
            }
            // Otherwise, return the method name (could be obfuscated for non-P/Invoke)
            Some(assembly.methods().get(&token)?.value().name.clone())
        }
        // MemberRef - external method reference, use the name directly
        0x0A => Some(assembly.refs_members().get(&token)?.value().name.clone()),
        _ => None,
    }
}

/// Determines the most likely anti-tamper mode based on detection results.
fn determine_mode(result: &AntiTamperDetectionResult) -> Option<AntiTamperMode> {
    if result.methods.is_empty() {
        return None;
    }

    // Count votes for each mode
    let mut normal_votes = 0;
    let mut anti_votes = 0;
    let mut jit_votes = 0;

    for method in &result.methods {
        match method.mode {
            AntiTamperMode::Normal => normal_votes += 1,
            AntiTamperMode::Anti => anti_votes += 1,
            AntiTamperMode::Jit => jit_votes += 1,
            AntiTamperMode::Unknown => {}
        }
    }

    // JIT mode is mutually exclusive with Normal/Anti
    if jit_votes > 0 {
        return Some(AntiTamperMode::Jit);
    }

    // Anti mode implies Normal mode detection too
    if anti_votes > 0 {
        return Some(AntiTamperMode::Anti);
    }

    if normal_votes > 0 {
        return Some(AntiTamperMode::Normal);
    }

    // If we have encrypted methods but couldn't determine mode
    if result.encrypted_method_count > 0 {
        return Some(AntiTamperMode::Unknown);
    }

    None
}

/// Maximum bytes to read when extracting a method body from memory.
/// This is generous - most methods are under 1KB.
const MAX_METHOD_BODY_SIZE: usize = 65536;

/// Finds all methods with non-zero RVAs.
///
/// This includes both methods with valid bodies and encrypted methods.
/// Used when we need to re-extract all method bodies to handle section layout changes.
fn find_all_methods_with_rva(assembly: &CilObject) -> Vec<Token> {
    assembly
        .methods()
        .iter()
        .filter_map(|entry| {
            let method = entry.value();
            if method.rva.is_some_and(|rva| rva > 0) {
                Some(method.token)
            } else {
                None
            }
        })
        .collect()
}

/// Extracts a decrypted method body from emulator memory at the given RVA.
///
/// This function:
/// 1. Reads bytes from the virtual memory at ImageBase + RVA
/// 2. Parses the method body to validate and determine size
/// 3. Re-encodes to canonical format
/// 4. Returns the bytes ready for storage in .text section
///
/// # Arguments
///
/// * `memory` - Slice of the virtual image (loaded at ImageBase)
/// * `rva` - The RVA where the method body is located
///
/// # Returns
///
/// The method body bytes (header + IL code + exception handlers), or None if
/// the method body couldn't be parsed.
fn extract_method_body_at_rva(memory: &[u8], rva: u32) -> Option<Vec<u8>> {
    let rva_usize = rva as usize;
    if rva_usize >= memory.len() {
        return None;
    }

    // Read up to MAX_METHOD_BODY_SIZE bytes or until end of memory
    let available = memory.len() - rva_usize;
    let read_size = available.min(MAX_METHOD_BODY_SIZE);
    let body_slice = &memory[rva_usize..rva_usize + read_size];

    // Parse the method body to validate and get IL code range
    let body = MethodBody::from(body_slice).ok()?;

    // Extract just the IL code (after header)
    let il_start = body.size_header;
    let il_end = il_start + body.size_code;
    if il_end > body_slice.len() {
        return None;
    }
    let il_code = &body_slice[il_start..il_end];

    // Re-encode to canonical format
    let mut output = Vec::new();
    body.write_to(&mut output, il_code).ok()?;

    Some(output)
}

/// Gets the RVA for a method from the raw MethodDef table.
fn get_method_rva(assembly: &CilObject, token: Token) -> Option<u32> {
    let tables = assembly.tables()?;
    let method_table = tables.table::<MethodDefRaw>()?;
    let row = token.row();
    let method_row = method_table.get(row)?;
    Some(method_row.rva)
}

/// Result of extracting decrypted method bodies.
#[derive(Debug)]
struct ExtractedMethodBodies {
    /// Map of method token to decrypted body bytes.
    bodies: Vec<(Token, Vec<u8>)>,
    /// Number of methods that couldn't be extracted.
    failed_count: usize,
}

/// Extracts all decrypted method bodies from emulator memory.
///
/// For each encrypted method, reads and parses its body from the
/// decrypted virtual image.
fn extract_decrypted_bodies(
    assembly: &CilObject,
    virtual_image: &[u8],
    encrypted_methods: &[Token],
) -> ExtractedMethodBodies {
    let mut bodies = Vec::new();
    let mut failed_count = 0;

    for &token in encrypted_methods {
        let Some(rva) = get_method_rva(assembly, token) else {
            failed_count += 1;
            continue;
        };

        if rva == 0 || rva as usize >= virtual_image.len() {
            failed_count += 1;
            continue;
        }

        match extract_method_body_at_rva(virtual_image, rva) {
            Some(body_bytes) => {
                bodies.push((token, body_bytes));
            }
            None => {
                failed_count += 1;
            }
        }
    }

    ExtractedMethodBodies {
        bodies,
        failed_count,
    }
}

/// Result of extracting decrypted field data.
#[derive(Debug)]
struct ExtractedFieldData {
    /// Map of field RID to (original_rva, decrypted_data).
    fields: Vec<(u32, u32, Vec<u8>)>,
    /// Number of fields that couldn't be extracted.
    failed_count: usize,
}

/// Extracts decrypted FieldRVA data from emulator memory.
///
/// Anti-tamper encrypts not just method bodies but also the Constants section,
/// which includes FieldRVA data. This function extracts the decrypted field
/// initialization data from the virtual image.
fn extract_decrypted_field_data(assembly: &CilObject, virtual_image: &[u8]) -> ExtractedFieldData {
    let mut fields = Vec::new();
    let mut failed_count = 0;

    // Get FieldRVA table
    let Some(tables) = assembly.tables() else {
        return ExtractedFieldData {
            fields,
            failed_count,
        };
    };

    let Some(fieldrva_table) = tables.table::<FieldRvaRaw>() else {
        return ExtractedFieldData {
            fields,
            failed_count,
        };
    };

    for row in fieldrva_table.iter() {
        let rva = row.rva;
        if rva == 0 {
            continue;
        }

        // Get field size from ClassLayout table
        let field_size = match get_field_data_size(assembly, row.field) {
            Some(size) => size,
            None => {
                failed_count += 1;
                continue;
            }
        };

        // Extract data from virtual image at the RVA
        let rva_usize = rva as usize;
        if rva_usize + field_size > virtual_image.len() {
            failed_count += 1;
            continue;
        }

        let data = virtual_image[rva_usize..rva_usize + field_size].to_vec();
        fields.push((row.rid, rva, data));
    }

    ExtractedFieldData {
        fields,
        failed_count,
    }
}

/// Gets the size of field data based on ClassLayout table.
///
/// For FieldRVA entries, the field must be a value type with explicit size
/// defined in ClassLayout. This function looks up that size.
fn get_field_data_size(assembly: &CilObject, field_rid: u32) -> Option<usize> {
    let tables = assembly.tables()?;
    let blobs = assembly.blob()?;

    // Get the Field row
    let field_table = tables.table::<FieldRaw>()?;
    let field_row = field_table.get(field_rid)?;

    // Parse field signature to get the value type token
    let sig_data = blobs.get(field_row.signature as usize).ok()?;
    let field_sig = parse_field_signature(sig_data).ok()?;

    // For value types, look up ClassLayout
    match &field_sig.base {
        TypeSignature::ValueType(token) => {
            // Only TypeDef tokens have ClassLayout entries
            if token.table() != 0x02 {
                return None;
            }
            let type_rid = token.row();

            let class_layout_table = tables.table::<ClassLayoutRaw>()?;
            for layout in class_layout_table.iter() {
                if layout.parent == type_rid {
                    return Some(layout.class_size as usize);
                }
            }
            None
        }
        _ => None,
    }
}

/// Result of anti-tamper emulation.
///
/// Contains the decrypted virtual image and metadata about the emulation.
#[derive(Debug)]
struct EmulationResult {
    /// The decrypted virtual image (PE loaded at ImageBase).
    virtual_image: Vec<u8>,
    /// Number of methods that were encrypted before decryption.
    encrypted_methods: Vec<Token>,
    /// The method token that performed decryption.
    decryptor_method: Token,
    /// Number of instructions executed during emulation.
    instructions_executed: u64,
}

/// Decrypts anti-tamper protected method bodies and returns a new assembly.
///
/// This function uses the CilAssembly modification API to rebuild method bodies
/// in the normal .text section rather than keeping them in the encrypted section.
/// This results in a cleaner output that can be further analyzed or executed.
///
/// # Process
///
/// 1. Emulates the anti-tamper initialization to decrypt method bodies in memory
/// 2. Extracts decrypted method bodies from the virtual image
/// 3. Creates a CilAssembly and stores each body via the modification API
/// 4. Updates MethodDef RVAs to point to the new locations
/// 5. Writes the assembly with bodies in the standard .text section
///
/// # Arguments
///
/// * `assembly` - The anti-tamper protected assembly.
/// * `events` - Event log for recording deobfuscation activity.
/// * `tracing` - Optional tracing configuration for emulation debugging.
///
/// # Returns
///
/// A new [`CilObject`] with decrypted method bodies in the .text section.
///
/// # Errors
///
/// Returns an error if emulation, extraction, or assembly writing fails.
pub fn decrypt_bodies(
    assembly: CilObject,
    events: &mut EventLog,
    tracing: Option<TracingConfig>,
) -> Result<CilObject> {
    let assembly_arc = Arc::new(assembly);

    // Step 1: Emulate anti-tamper to get decrypted virtual image
    let emulation_result = emulate_antitamper(Arc::clone(&assembly_arc), tracing)?;

    // Log emulation completion
    events.info(format!(
        "Anti-tamper emulation completed: {} instructions executed via method 0x{:08x}",
        emulation_result.instructions_executed,
        emulation_result.decryptor_method.value()
    ));

    // Step 2: Find ALL methods with RVAs (not just encrypted ones)
    // This is necessary because the assembly writer may change section layout,
    // which would invalidate existing RVAs. By extracting ALL method bodies
    // from the decrypted virtual image, we ensure all RVAs get updated correctly.
    let all_methods_with_rva = find_all_methods_with_rva(&assembly_arc);

    // Step 3: Extract ALL method bodies from virtual image
    let extracted = extract_decrypted_bodies(
        &assembly_arc,
        &emulation_result.virtual_image,
        &all_methods_with_rva,
    );

    if extracted.bodies.is_empty() {
        return Err(Error::Deobfuscation(
            "No method bodies could be extracted from decrypted image".to_string(),
        ));
    }

    // Log warning if some extractions failed
    if extracted.failed_count > 0 {
        events.warn(format!(
            "Failed to extract {} method bodies from decrypted image",
            extracted.failed_count
        ));
    }

    // Log each decrypted method body
    let encrypted_count = emulation_result.encrypted_methods.len();
    for &token in &emulation_result.encrypted_methods {
        events
            .record(EventKind::MethodBodyDecrypted)
            .method(token)
            .message(format!("Decrypted method body 0x{:08x}", token.value()));
    }

    // Step 4: Create CilAssembly from original PE bytes
    let mut cil_assembly = CilAssembly::from_bytes_with_validation(
        assembly_arc.file().data().to_vec(),
        ValidationConfig::analysis(),
    )?;

    // Step 5: Store each body and update MethodDef RVAs
    for (method_token, body_bytes) in extracted.bodies {
        // Store the method body - returns a placeholder RVA
        let placeholder_rva = cil_assembly.store_method_body(body_bytes);

        // Get the existing MethodDef row
        let rid = method_token.row();
        let existing_row = cil_assembly
            .view()
            .tables()
            .and_then(|t| t.table::<MethodDefRaw>())
            .and_then(|table| table.get(rid))
            .ok_or_else(|| Error::Deobfuscation(format!("MethodDef row {rid} not found")))?;

        // Create updated row with new RVA
        let updated_row = MethodDefRaw {
            rid: existing_row.rid,
            token: existing_row.token,
            offset: existing_row.offset,
            rva: placeholder_rva,
            impl_flags: existing_row.impl_flags,
            flags: existing_row.flags,
            name: existing_row.name,
            signature: existing_row.signature,
            param_list: existing_row.param_list,
        };

        // Update the MethodDef row
        cil_assembly.table_row_update(
            TableId::MethodDef,
            rid,
            TableDataOwned::MethodDef(updated_row),
        )?;
    }

    // Step 5b: Extract and store decrypted FieldRVA data
    // Anti-tamper also encrypts the Constants section which contains FieldRVA data
    let extracted_fields =
        extract_decrypted_field_data(&assembly_arc, &emulation_result.virtual_image);

    let field_count = extracted_fields.fields.len();
    if extracted_fields.failed_count > 0 {
        events.warn(format!(
            "Failed to extract {} field data entries from decrypted image",
            extracted_fields.failed_count
        ));
    }

    // Store decrypted field data and update FieldRVA rows
    for (rid, _original_rva, data) in extracted_fields.fields {
        // Store the field data - returns a placeholder RVA
        let placeholder_rva = cil_assembly.store_field_data(data);

        // Get the existing FieldRVA row
        let existing_row = cil_assembly
            .view()
            .tables()
            .and_then(|t| t.table::<FieldRvaRaw>())
            .and_then(|table| table.get(rid))
            .ok_or_else(|| Error::Deobfuscation(format!("FieldRVA row {rid} not found")))?;

        // Create updated row with new RVA
        let updated_row = FieldRvaRaw {
            rid: existing_row.rid,
            token: existing_row.token,
            offset: existing_row.offset,
            rva: placeholder_rva,
            field: existing_row.field,
        };

        // Update the FieldRVA row
        cil_assembly.table_row_update(
            TableId::FieldRVA,
            rid,
            TableDataOwned::FieldRVA(updated_row),
        )?;
    }

    // Log anti-tamper removal summary
    events.record(EventKind::AntiTamperRemoved).message(format!(
        "Anti-tamper protection removed: {} method bodies, {} field data entries decrypted",
        encrypted_count, field_count
    ));

    // Step 6: Write the modified assembly and reload
    // Use skip_original_method_bodies because we've decrypted and stored ALL method bodies
    // from the virtual image - the original encrypted bodies are no longer needed
    let config = GeneratorConfig::default().with_skip_original_method_bodies(true);
    cil_assembly.into_cilobject_with(ValidationConfig::analysis(), config)
}

/// Emulates anti-tamper decryption and returns the decrypted virtual image.
///
/// This function:
/// 1. Loads the PE into emulator memory at ImageBase
/// 2. Finds the anti-tamper initialization method
/// 3. Emulates it with stubbed GetHINSTANCE/VirtualProtect
/// 4. Returns the decrypted virtual image from memory
///
/// The virtual image is the PE loaded at ImageBase with sections at their
/// virtual addresses - this is where the decrypted method bodies reside.
///
/// # Arguments
///
/// * `assembly` - The anti-tamper protected assembly.
/// * `pe_bytes` - The raw PE file bytes.
///
/// # Returns
///
/// An [`EmulationResult`] containing the decrypted virtual image and metadata.
///
/// # Errors
///
/// Returns an error if:
/// - No anti-tamper method is found
/// - Emulation fails
/// - Memory extraction fails
fn emulate_antitamper(
    assembly: Arc<CilObject>,
    tracing: Option<TracingConfig>,
) -> Result<EmulationResult> {
    // Use scored candidate detection to find the best anti-tamper initialization method
    let candidates = find_candidates(&assembly, ProtectionType::AntiTamper);
    let decryptor_method = candidates.best().map(|c| c.token).ok_or_else(|| {
        Error::Deobfuscation("No anti-tamper initialization method found".to_string())
    })?;

    // Find encrypted methods before decryption
    let encrypted_methods = find_encrypted_methods(&assembly);

    // Build the emulation process using ProcessBuilder.
    // ProcessBuilder automatically maps the assembly's PE image when .assembly_arc() is used.
    // All required stubs (GetHINSTANCE, VirtualProtect, VirtualAlloc, reflection, IntPtr, etc.)
    // are automatically registered by the emulation runtime.
    let mut builder = ProcessBuilder::new()
        .assembly_arc(Arc::clone(&assembly))
        .name("anti-tamper-emulation")
        .with_max_instructions(10_000_000)
        .with_max_call_depth(200)
        .with_timeout_ms(120_000); // 2 minutes - anti-tamper can be slow

    // Add tracing if configured, with anti-tamper context prefix
    if let Some(mut tracing_config) = tracing {
        tracing_config.context_prefix = Some("anti-tamper".to_string());
        builder = builder.with_tracing(tracing_config);
    }

    let process = builder.build()?;

    // Get the loaded image info for extracting decrypted data later
    let loaded_image = process
        .primary_image()
        .ok_or_else(|| Error::Deobfuscation("Failed to get loaded PE image info".to_string()))?;
    let pe_base = loaded_image.base_address;
    let virtual_size = loaded_image.size_of_image as usize;

    let outcome = process.execute_method(decryptor_method, vec![])?;
    let instructions_executed = match outcome {
        EmulationOutcome::Completed { instructions, .. }
        | EmulationOutcome::Breakpoint { instructions, .. } => instructions,
        EmulationOutcome::LimitReached { limit, .. } => {
            return Err(Error::Deobfuscation(format!(
                "Anti-tamper emulation exceeded limit: {:?}",
                limit
            )));
        }
        EmulationOutcome::Stopped { reason, .. } => {
            return Err(Error::Deobfuscation(format!(
                "Anti-tamper emulation stopped: {}",
                reason
            )));
        }
        EmulationOutcome::UnhandledException { exception, .. } => {
            return Err(Error::Deobfuscation(format!(
                "Anti-tamper emulation threw exception: {:?}",
                exception
            )));
        }
        EmulationOutcome::RequiresSymbolic { reason, .. } => {
            return Err(Error::Deobfuscation(format!(
                "Anti-tamper emulation requires symbolic execution: {}",
                reason
            )));
        }
    };

    // Extract the decrypted virtual image from memory
    let virtual_image = process.read_memory(pe_base, virtual_size)?;

    Ok(EmulationResult {
        virtual_image,
        encrypted_methods,
        decryptor_method,
        instructions_executed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLES_DIR: &str = "tests/samples/packers/confuserex";

    /// Test that the original (unprotected) sample has no anti-tamper.
    #[test]
    fn test_original_no_antitamper() -> crate::Result<()> {
        let path = format!("{}/original.exe", SAMPLES_DIR);
        let assembly = CilObject::from_path_with_validation(&path, ValidationConfig::analysis())?;

        let result = detect_antitamper(&assembly);

        assert!(
            result.methods.is_empty(),
            "Original should have no anti-tamper methods"
        );
        assert_eq!(
            result.encrypted_method_count, 0,
            "Original should have no encrypted methods"
        );
        assert!(
            result.pinvoke_methods.is_empty(),
            "Original should have no anti-tamper P/Invoke"
        );
        assert!(!result.is_detected());

        Ok(())
    }

    /// Test that the normal preset sample has no anti-tamper.
    #[test]
    fn test_normal_no_antitamper() -> crate::Result<()> {
        let path = format!("{}/mkaring_normal.exe", SAMPLES_DIR);
        let assembly = CilObject::from_path_with_validation(&path, ValidationConfig::analysis())?;

        let result = detect_antitamper(&assembly);

        // Normal preset should NOT have anti-tamper (it's Maximum only)
        assert_eq!(
            result.encrypted_method_count, 0,
            "Normal preset should have no encrypted methods"
        );

        Ok(())
    }

    /// Test that the standalone antitamper sample has anti-tamper protection.
    #[test]
    fn test_antitamper_sample_detection() -> crate::Result<()> {
        let path = format!("{}/mkaring_antitamper.exe", SAMPLES_DIR);
        let assembly = CilObject::from_path_with_validation(&path, ValidationConfig::analysis())?;

        let result = detect_antitamper(&assembly);

        assert!(
            result.encrypted_method_count > 0,
            "Antitamper sample should have encrypted methods, found {}",
            result.encrypted_method_count
        );
        assert!(result.is_detected(), "Anti-tamper should be detected");
        assert!(
            result.best_init_method().is_some(),
            "Should identify an anti-tamper initialization method"
        );

        Ok(())
    }

    /// Test that the standalone antitamper sample can be decrypted.
    #[test]
    fn test_antitamper_sample_decryption() -> crate::Result<()> {
        let path = format!("{}/mkaring_antitamper.exe", SAMPLES_DIR);
        let assembly = CilObject::from_path_with_validation(&path, ValidationConfig::analysis())?;

        // Get encrypted methods before decryption
        let encrypted_before = find_encrypted_methods(&assembly);
        assert!(
            !encrypted_before.is_empty(),
            "Should have encrypted methods before decryption"
        );

        // Decrypt the assembly
        let mut events = EventLog::new();
        let decrypted = decrypt_bodies(assembly, &mut events, None)?;

        // Verify no encrypted methods remain
        let encrypted_after = find_encrypted_methods(&decrypted);
        assert!(
            encrypted_after.is_empty(),
            "Should have no encrypted methods after decryption, found {}",
            encrypted_after.len()
        );

        // Verify decrypted methods have valid IL bodies
        for token in &encrypted_before {
            let method_entry = decrypted.methods().get(token);
            assert!(
                method_entry.is_some(),
                "Method 0x{:08X} should exist",
                token.value()
            );
            let entry = method_entry.unwrap();
            let method = entry.value();
            let body = method.body.get();
            assert!(
                body.is_some(),
                "Decrypted method 0x{:08X} should have a body",
                token.value()
            );
        }

        Ok(())
    }

    /// Test that the maximum preset sample has anti-tamper protection.
    #[test]
    fn test_maximum_detection() -> crate::Result<()> {
        let path = format!("{}/mkaring_maximum.exe", SAMPLES_DIR);
        let assembly = CilObject::from_path_with_validation(&path, ValidationConfig::analysis())?;

        let result = detect_antitamper(&assembly);

        assert!(
            result.encrypted_method_count > 0,
            "Maximum should have encrypted methods, found {}",
            result.encrypted_method_count
        );
        assert!(result.is_detected(), "Anti-tamper should be detected");
        assert!(
            result.best_init_method().is_some(),
            "Should identify an anti-tamper initialization method"
        );

        Ok(())
    }

    /// Test that the maximum preset sample can be decrypted.
    #[test]
    #[cfg(not(feature = "skip-expensive-tests"))]
    fn test_maximum_decryption() -> crate::Result<()> {
        let path = format!("{}/mkaring_maximum.exe", SAMPLES_DIR);
        let assembly = CilObject::from_path_with_validation(&path, ValidationConfig::analysis())?;

        // Get encrypted methods before decryption
        let encrypted_before = find_encrypted_methods(&assembly);
        assert!(
            !encrypted_before.is_empty(),
            "Should have encrypted methods before decryption"
        );

        // Decrypt the assembly
        let mut events = EventLog::new();
        let decrypted = decrypt_bodies(assembly, &mut events, None)?;

        // Verify no encrypted methods remain
        let encrypted_after = find_encrypted_methods(&decrypted);
        assert!(
            encrypted_after.is_empty(),
            "Should have no encrypted methods after decryption, found {}",
            encrypted_after.len()
        );

        // Verify decrypted methods have valid IL bodies
        for token in &encrypted_before {
            let method_entry = decrypted.methods().get(token);
            assert!(
                method_entry.is_some(),
                "Method 0x{:08X} should exist",
                token.value()
            );
            let entry = method_entry.unwrap();
            let method = entry.value();
            let body = method.body.get();
            assert!(
                body.is_some(),
                "Decrypted method 0x{:08X} should have a body",
                token.value()
            );
        }

        Ok(())
    }
}
