//! BitMono detection logic.
//!
//! Identifies assemblies protected by BitMono through comprehensive multi-signal
//! detection covering all 16 protections across 4 categories:
//!
//! 1. **Reversible IL-level** — StringsEncryption, CallToCalli, DotNetHook,
//!    UnmanagedString, BitMethodDotnet, AntiDebugBreakpoints
//! 2. **Lossy IL-level** — FullRenamer, NoNamespaces, ObjectReturnType (detection only)
//! 3. **Cleanup targets** — AntiILdasm, AntiDe4dot, BillionNops, AntiDecompiler
//! 4. **PE-level packers** — BitDotNet, BitDecompiler, BitMono packer, BitTimeDateStamp
//!
//! Unlike ConfuserEx (layered/interdependent) or Obfuscar (single technique), BitMono
//! protections are independent plugins. Each can be detected individually.
//!
//! Detection threshold: 20. Key discriminators from ConfuserEx/Obfuscar:
//! - BitMono uses `Rfc2898DeriveBytes` + `RijndaelManaged` (not LZMA + custom XOR)
//! - BitMono's FullRenamer produces space-containing names (not Unicode unprintable)
//! - BitMono's `calli` has distinctive `ldtoken <Module>` + `ResolveMethod` sequence
//! - Obfuscar's helper type uses `<PrivateImplementationDetails>{GUID}` — not used by BitMono

use crate::{
    deobfuscation::{
        detection::{DetectionEvidence, DetectionScore},
        findings::DeobfuscationFindings,
        obfuscators::utils,
    },
    file::repair::RepairAction,
    metadata::{
        method::{MethodBody, MethodImplCodeType},
        signatures::TypeSignature,
        tables::{
            CustomAttributeRaw, MemberRefRaw, MethodDefRaw, TableId, TypeAttributes, TypeDefRaw,
            TypeRefRaw,
        },
        token::Token,
    },
    CilObject,
};

/// Detects BitMono obfuscation in an assembly.
///
/// Populates findings **in place** (does NOT create fresh findings and overwrite —
/// pe_repairs must survive). Covers all 16 protections.
///
/// # Returns
///
/// A `DetectionScore` indicating confidence level and evidence.
pub fn detect_bitmono(
    assembly: &CilObject,
    findings: &mut DeobfuscationFindings,
) -> DetectionScore {
    let score = DetectionScore::new();

    // PE-level packer evidence (reads findings.pe_repairs)
    score_pe_repairs(findings, &score);

    // IL-level: string encryption infrastructure
    detect_string_encryption(assembly, &score, findings);

    // IL-level: CallToCalli pattern
    detect_call_to_calli(assembly, &score, findings);

    // IL-level: DotNetHook infrastructure
    detect_dotnethook(assembly, &score, findings);

    // IL-level: UnmanagedString native methods
    detect_unmanaged_string(assembly, &score, findings);

    // IL-level: BitMethodDotnet junk prefix
    detect_junk_prefix(assembly, &score, findings);

    // IL-level: AntiDebugBreakpoints timing checks
    detect_antidebug_breakpoints(assembly, &score, findings);

    // IL-level: BillionNops dead method
    detect_billion_nops(assembly, &score, findings);

    // IL-level: AntiDecompiler invalid attributes
    detect_antidecompiler(assembly, &score, findings);

    // IL-level: Malformed exception handlers
    detect_malformed_exception_handlers(assembly, &score, findings);

    // Metadata: SuppressIldasmAttribute (shared utility)
    utils::check_suppress_ildasm(assembly, &score, findings, 10);

    // Metadata: AntiDe4dot fake attributes
    detect_antide4dot_attributes(assembly, &score, findings);

    // Naming: FullRenamer space-containing names
    detect_renamer_names(assembly, &score);

    score
}

/// Scores PE repair evidence from `findings.pe_repairs`.
///
/// BitMono's PE-level protections produce characteristic repair patterns:
/// - `PeSignature { original: 0x00014550 }` → BitDotNet (+40)
/// - `ClrHeaderSize { original: 0 }` → BitDotNet/BitDecompiler (+25)
/// - `ClrHeaderVersion { original_major: 0 }` → supporting (+10)
/// - `ClrMetadataRva` → supporting (+10)
/// - `DataDirectoryCount { original: 0x13 }` → BitMono packer (+40)
/// - `DotNetDirectorySize { original: 0 }` → supporting (+10)
fn score_pe_repairs(findings: &DeobfuscationFindings, score: &DetectionScore) {
    for repair in &findings.pe_repairs {
        match repair {
            RepairAction::PeSignature { original, .. } if *original == 0x0001_4550 => {
                score.add(DetectionEvidence::StructuralPattern {
                    description: format!("BitDotNet PE signature corruption (0x{:08X})", original),
                    confidence: 40,
                });
            }
            RepairAction::ClrHeaderSize { original, .. } if *original == 0 => {
                score.add(DetectionEvidence::StructuralPattern {
                    description: "BitDotNet/BitDecompiler CLR header size zeroed".to_string(),
                    confidence: 30,
                });
            }
            RepairAction::ClrHeaderVersion { original_major, .. } if *original_major == 0 => {
                score.add(DetectionEvidence::StructuralPattern {
                    description: "CLR runtime version zeroed (supporting evidence)".to_string(),
                    confidence: 10,
                });
            }
            RepairAction::ClrMetadataRva { .. } => {
                score.add(DetectionEvidence::StructuralPattern {
                    description: "CLR metadata RVA reconstructed (supporting evidence)".to_string(),
                    confidence: 10,
                });
            }
            RepairAction::DataDirectoryCount { original, .. } if *original == 0x13 => {
                score.add(DetectionEvidence::StructuralPattern {
                    description: format!(
                        "BitMono packer data directory inflation (0x{:X})",
                        original
                    ),
                    confidence: 40,
                });
            }
            RepairAction::DotNetDirectorySize { original, .. } if *original == 0 => {
                score.add(DetectionEvidence::StructuralPattern {
                    description: ".NET directory size zeroed (supporting evidence)".to_string(),
                    confidence: 10,
                });
            }
            _ => {}
        }
    }
}

/// Detects BitMono StringsEncryption.
///
/// Looks for a static method in `<Module>` that:
/// 1. Has references to `RijndaelManaged`/`Aes` + `Rfc2898DeriveBytes` + `CryptoStream`
///    in its instruction stream (via call/newobj targets)
/// 2. Optionally has a characteristic call pattern with `ldsfld byte[]` args
///
/// Confidence: +40 if decryptor found, +15 additional if >= 3 call sites.
fn detect_string_encryption(
    assembly: &CilObject,
    score: &DetectionScore,
    findings: &mut DeobfuscationFindings,
) {
    let mut decryptor_found = false;

    // Scan ALL methods because BitMono may place the decryptor in any type,
    // not just <Module> (the strings sample has 0 methods in <Module>).
    for method_entry in assembly.methods() {
        let method = method_entry.value();

        // Look for static methods that reference crypto types
        if !method.is_static() || method.name == ".cctor" || method.name == ".ctor" {
            continue;
        }

        let instructions: Vec<_> = method.instructions().collect();
        if instructions.is_empty() {
            continue;
        }

        // Scan for crypto-related references: RijndaelManaged/Aes + Rfc2898DeriveBytes
        let mut has_aes = false;
        let mut has_key_derivation = false;
        let mut has_crypto_stream = false;

        for instr in &instructions {
            if let Some(token) = instr.get_token_operand() {
                // Check MemberRef/TypeRef for crypto type names
                if let Some(name) = resolve_type_name_for_token(assembly, token) {
                    if name.contains("RijndaelManaged") || name.contains("Aes") {
                        has_aes = true;
                    }
                    if name.contains("Rfc2898DeriveBytes") {
                        has_key_derivation = true;
                    }
                    if name.contains("CryptoStream") {
                        has_crypto_stream = true;
                    }
                }
            }
        }

        if has_aes && has_key_derivation {
            decryptor_found = true;
            findings.decryptor_methods.push(method.token);

            // Tag the decryptor's declaring type as infrastructure so cleanup
            // removes the entire crypto helper type (all ~39 methods/fields).
            if let Some(decl_type) = method.declaring_type_rc() {
                findings
                    .protection_infrastructure_types
                    .push(decl_type.token);
            }

            let description = if has_crypto_stream {
                "BitMono string decryptor (AES + Rfc2898DeriveBytes + CryptoStream)"
            } else {
                "BitMono string decryptor (AES + Rfc2898DeriveBytes)"
            };

            score.add(DetectionEvidence::StructuralPattern {
                description: description.to_string(),
                confidence: 40,
            });
            break; // Only one decryptor expected
        }
    }

    // Fallback: if crypto name scanning failed, look for a method with
    // the characteristic BitMono decryptor signature: static, returns string,
    // takes 3+ byte[] parameters.
    if !decryptor_found {
        for method_entry in assembly.methods() {
            let method = method_entry.value();
            if !method.is_static() || method.name == ".cctor" || method.name == ".ctor" {
                continue;
            }
            if method_matches_decryptor_signature(method) {
                decryptor_found = true;
                findings.decryptor_methods.push(method.token);

                // Tag the decryptor's declaring type as infrastructure
                if let Some(decl_type) = method.declaring_type_rc() {
                    findings
                        .protection_infrastructure_types
                        .push(decl_type.token);
                }

                score.add(DetectionEvidence::StructuralPattern {
                    description:
                        "BitMono string decryptor (signature: string(byte[], byte[], byte[]))"
                            .to_string(),
                    confidence: 40,
                });
                break;
            }
        }
    }

    // Check for call sites (ldsfld byte[] patterns calling the decryptor)
    if decryptor_found {
        let mut call_site_count = 0usize;
        for method_entry in assembly.methods() {
            let method = method_entry.value();
            for instr in method.instructions() {
                if instr.mnemonic == "call" || instr.mnemonic == "callvirt" {
                    if let Some(token) = instr.get_token_operand() {
                        if findings.decryptor_methods.iter().any(|(_, t)| *t == token) {
                            call_site_count += 1;
                        }
                    }
                }
            }
        }

        if call_site_count >= 3 {
            score.add(DetectionEvidence::StructuralPattern {
                description: format!(
                    "BitMono string decryptor called from {} sites",
                    call_site_count
                ),
                confidence: 15,
            });
        }
    }
}

/// Detects BitMono CallToCalli pattern.
///
/// Scans for the distinctive sequence: `ldtoken <Module>` → `GetTypeFromHandle` →
/// `get_Module` → `ldc.i4 0x06XXXXXX` → `ResolveMethod` → `GetFunctionPointer` → `calli`
///
/// Confidence: +25 if >= 3 instances found.
fn detect_call_to_calli(
    assembly: &CilObject,
    score: &DetectionScore,
    findings: &mut DeobfuscationFindings,
) {
    let mut calli_count = 0usize;

    for method_entry in assembly.methods() {
        let method = method_entry.value();
        let instructions: Vec<_> = method.instructions().collect();

        // Look for ldtoken + ... + calli pattern
        let mut i = 0;
        while i < instructions.len() {
            if instructions[i].mnemonic == "calli" {
                // Walk backwards to check for the characteristic pattern
                // Look for: ldtoken somewhere before + ResolveMethod-related calls
                let window_start = i.saturating_sub(12);
                let window = &instructions[window_start..i];

                let has_ldtoken = window.iter().any(|instr| instr.mnemonic == "ldtoken");
                let has_resolve_method = window.iter().any(|instr| {
                    if let Some(token) = instr.get_token_operand() {
                        if let Some(name) = resolve_member_name(assembly, token) {
                            return name.contains("ResolveMethod")
                                || name.contains("GetFunctionPointer");
                        }
                    }
                    false
                });

                if has_ldtoken && has_resolve_method {
                    calli_count += 1;
                }
            }
            i += 1;
        }
    }

    findings.init_bitmono().calltocalli_count = calli_count;

    if calli_count >= 3 {
        score.add(DetectionEvidence::BytecodePattern {
            name: "BitMono CallToCalli pattern".to_string(),
            locations: boxcar::Vec::new(),
            confidence: 25,
        });
    }
}

/// Detects BitMono DotNetHook infrastructure.
///
/// Looks for a type containing methods with:
/// 1. `RuntimeHelpers.PrepareMethod` or `GetFunctionPointer` (JIT hooking setup)
/// 2. `Marshal.WriteByte`/`Marshal.WriteInt64`/`Marshal.WriteInt32` (memory patching)
///
/// These are external MemberRef references that survive renaming, unlike
/// `VirtualProtect` P/Invoke which may be renamed by FullRenamer.
///
/// Confidence: +30 if found.
fn detect_dotnethook(
    assembly: &CilObject,
    score: &DetectionScore,
    findings: &mut DeobfuscationFindings,
) {
    for type_entry in assembly.types().iter() {
        let cil_type = type_entry.value();

        let mut has_jit_hook_setup = false;
        let mut has_marshal_write = false;

        for (_, method_ref) in cil_type.methods.iter() {
            let Some(method) = method_ref.upgrade() else {
                continue;
            };

            for instr in method.instructions() {
                if let Some(token) = instr.get_token_operand() {
                    if let Some(name) = resolve_member_name(assembly, token) {
                        // JIT hooking setup: PrepareMethod forces JIT compilation,
                        // GetFunctionPointer gets the native code address to patch
                        if name.contains("PrepareMethod")
                            || name.contains("GetFunctionPointer")
                            || name.contains("VirtualProtect")
                            || name.contains("mprotect")
                        {
                            has_jit_hook_setup = true;
                        }
                        if name.contains("Marshal") && name.contains("Write") {
                            has_marshal_write = true;
                        }
                    }
                }
            }
        }

        if has_jit_hook_setup && has_marshal_write {
            findings.init_bitmono().dotnethook_count += 1;
            score.add(DetectionEvidence::StructuralPattern {
                description: format!(
                    "BitMono DotNetHook infrastructure in type '{}.{}'",
                    cil_type.namespace, cil_type.name
                ),
                confidence: 30,
            });
            findings
                .protection_infrastructure_types
                .push(cil_type.token);

            // Identify the RedirectStub method by signature so reversal works
            // even when FullRenamer has renamed all method names.
            // RedirectStub: static void(int32, int32) with PrepareMethod/GetFunctionPointer calls.
            for (_, method_ref) in cil_type.methods.iter() {
                let Some(method) = method_ref.upgrade() else {
                    continue;
                };
                if !method.is_static() {
                    continue;
                }
                if !matches!(method.signature.return_type.base, TypeSignature::Void) {
                    continue;
                }
                if method.signature.params.len() != 2 {
                    continue;
                }
                let both_i4 = method
                    .signature
                    .params
                    .iter()
                    .all(|p| matches!(p.base, TypeSignature::I4));
                if !both_i4 {
                    continue;
                }
                // Verify body contains PrepareMethod or GetFunctionPointer
                let has_hook_api = method.instructions().any(|instr| {
                    instr
                        .get_token_operand()
                        .and_then(|t| resolve_member_name(assembly, t))
                        .is_some_and(|n| {
                            n.contains("PrepareMethod") || n.contains("GetFunctionPointer")
                        })
                });
                if has_hook_api {
                    findings.init_bitmono().dotnethook_redirect_stub = Some(method.token);
                    break;
                }
            }

            return; // Only one DotNetHook type expected
        }
    }
}

/// Detects BitMono UnmanagedString native methods.
///
/// Finds methods in `<Module>` with `Native` impl code type that are BitMono's
/// fake native string holders. BitMono sets BOTH the Native code type AND the
/// PINVOKE_IMPL flag, and uses GUID-format names (e.g. "260dce49-5827-...").
///
/// Detection: native methods in `<Module>` with GUID-like names, OR native
/// methods without PINVOKE (original detection for older BitMono versions).
///
/// Confidence: +20 if >= 3 such methods.
fn detect_unmanaged_string(
    assembly: &CilObject,
    score: &DetectionScore,
    findings: &mut DeobfuscationFindings,
) {
    let types = assembly.types();
    let Some(module_type) = types.module_type() else {
        return;
    };

    let mut fake_native_count = 0usize;

    for (_, method_ref) in module_type.methods.iter() {
        let Some(method) = method_ref.upgrade() else {
            continue;
        };

        if !method.is_code_native() {
            continue;
        }

        // Original check: native without PINVOKE (older BitMono versions)
        if !method.is_pinvoke() && !method.is_internal_call() {
            fake_native_count += 1;
            continue;
        }

        // BitMono sets PINVOKE_IMPL on fake native methods but names them
        // with GUIDs. Real P/Invoke methods have meaningful API names.
        if is_guid_name(&method.name) {
            fake_native_count += 1;
        }
    }

    findings.init_bitmono().unmanaged_string_count = fake_native_count;

    if fake_native_count >= 3 {
        // Scale confidence with the number of fake native methods.
        // GUID-named native methods are a very specific BitMono signal.
        // Base: 20, +1 per method beyond 3, capped at 50.
        let confidence = (20 + fake_native_count.saturating_sub(3)).min(50);
        score.add(DetectionEvidence::StructuralPattern {
            description: format!(
                "{} fake native methods in <Module> (BitMono UnmanagedString)",
                fake_native_count
            ),
            confidence,
        });
    }
}

/// Checks if a name matches the GUID format used by BitMono's UnmanagedString.
///
/// Pattern: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` (lowercase hex with dashes).
fn is_guid_name(name: &str) -> bool {
    if name.len() != 36 {
        return false;
    }
    let bytes = name.as_bytes();
    // Check dash positions: 8, 13, 18, 23
    if bytes[8] != b'-' || bytes[13] != b'-' || bytes[18] != b'-' || bytes[23] != b'-' {
        return false;
    }
    // Check all other characters are hex digits
    bytes.iter().enumerate().all(|(i, &b)| {
        if i == 8 || i == 13 || i == 18 || i == 23 {
            true
        } else {
            b.is_ascii_hexdigit()
        }
    })
}

/// Detects BitMono BitMethodDotnet junk prefix.
///
/// Scans method bodies for `br.s` at method start with a small forward jump
/// (1-10 bytes). BitMethodDotnet inserts `br.s` that branches over 1-3 bytes
/// of dead code to reach the original first instruction. The dead bytes may
/// decode as prefix opcodes, regular instructions, or anything else.
///
/// Confidence: +10 if >= 5 methods with this pattern.
fn detect_junk_prefix(
    assembly: &CilObject,
    score: &DetectionScore,
    findings: &mut DeobfuscationFindings,
) {
    use crate::assembly::{Immediate, Operand};

    let mut junk_method_count = 0usize;

    for method_entry in assembly.methods() {
        let method = method_entry.value();
        let instructions: Vec<_> = method.instructions().collect();

        if instructions.len() < 2 {
            continue;
        }

        // Check for br.s at method start with a small positive forward offset.
        // BitMethodDotnet inserts br.s that jumps over 1-10 bytes of junk.
        if instructions[0].mnemonic == "br.s" {
            let is_small_forward_jump = matches!(
                instructions[0].operand,
                Operand::Immediate(Immediate::Int8(1..=10))
            );
            if is_small_forward_jump {
                junk_method_count += 1;
            }
        }
    }

    findings.init_bitmono().junk_prefix_count = junk_method_count;

    if junk_method_count >= 5 {
        score.add(DetectionEvidence::StructuralPattern {
            description: format!(
                "{} methods with junk prefix pattern (BitMono BitMethodDotnet)",
                junk_method_count
            ),
            confidence: 10,
        });
    }
}

/// Detects BitMono AntiDebugBreakpoints timing checks.
///
/// Scans for `DateTime.UtcNow` + `op_Subtraction` + `TotalMilliseconds` pattern
/// combined with a timing threshold comparison.
///
/// Confidence: +20 if found.
fn detect_antidebug_breakpoints(
    assembly: &CilObject,
    score: &DetectionScore,
    findings: &mut DeobfuscationFindings,
) {
    let mut found_count = 0usize;

    for method_entry in assembly.methods() {
        let method = method_entry.value();
        let instructions: Vec<_> = method.instructions().collect();

        let mut has_utcnow = false;
        let mut has_subtraction = false;
        let mut has_total_ms = false;

        for instr in &instructions {
            if let Some(token) = instr.get_token_operand() {
                if let Some(name) = resolve_member_name(assembly, token) {
                    if name.contains("get_UtcNow") {
                        has_utcnow = true;
                    }
                    if name.contains("op_Subtraction") {
                        has_subtraction = true;
                    }
                    if name.contains("get_TotalMilliseconds") {
                        has_total_ms = true;
                    }
                }
            }
        }

        if has_utcnow && has_subtraction && has_total_ms {
            findings.anti_debug_methods.push(*method_entry.key());
            found_count += 1;
        }
    }

    if found_count > 0 {
        score.add(DetectionEvidence::StructuralPattern {
            description: format!(
                "BitMono AntiDebugBreakpoints timing check ({} methods)",
                found_count
            ),
            confidence: 20,
        });
    }
}

/// Detects BitMono BillionNops dead method.
///
/// Finds a method in `<Module>` with > 50,000 nop instructions.
///
/// Confidence: +10 if found.
fn detect_billion_nops(
    assembly: &CilObject,
    score: &DetectionScore,
    findings: &mut DeobfuscationFindings,
) {
    let types = assembly.types();
    let Some(module_type) = types.module_type() else {
        return;
    };

    for (_, method_ref) in module_type.methods.iter() {
        let Some(method) = method_ref.upgrade() else {
            continue;
        };

        let nop_count = method
            .instructions()
            .filter(|i| i.mnemonic == "nop")
            .count();

        if nop_count > 50_000 {
            findings
                .init_bitmono()
                .billion_nops_methods
                .push(method.token);
            score.add(DetectionEvidence::StructuralPattern {
                description: format!(
                    "BillionNops dead method with {} nop instructions",
                    nop_count
                ),
                confidence: 10,
            });
        }
    }
}

/// Detects BitMono AntiDecompiler invalid type attributes.
///
/// Finds nested types of `<Module>` with `Sealed | ExplicitLayout` attributes,
/// which confuse decompilers. Mono-only protection.
///
/// Confidence: +10 if found.
fn detect_antidecompiler(
    assembly: &CilObject,
    score: &DetectionScore,
    findings: &mut DeobfuscationFindings,
) {
    let types = assembly.types();
    let Some(module_type) = types.module_type() else {
        return;
    };

    for (_, nested_ref) in module_type.nested_types.iter() {
        let Some(nested) = nested_ref.upgrade() else {
            continue;
        };

        // AntiDecompiler sets Sealed (0x100) | ExplicitLayout (0x10) on nested <Module> types
        // Normal nested types of <Module> wouldn't have ExplicitLayout unless they're
        // legitimate value types (which are rare in <Module>)
        let has_explicit_layout = nested.flags.layout() == TypeAttributes::EXPLICIT_LAYOUT;
        if nested.is_sealed() && has_explicit_layout && nested.name != "<Module>" {
            // Skip compiler-generated data holder types (FieldRVA backing types).
            // StringsEncryption creates nested types with names like "<>" or "__Static"
            // that use ExplicitLayout for sizing, and types with 0-1 fields are data holders.
            if nested.name.starts_with("<>") || nested.name.starts_with("__Static") {
                continue;
            }
            if nested.fields.count() <= 1 {
                continue;
            }

            findings
                .init_bitmono()
                .anti_decompiler_types
                .push(nested.token);
        }
    }

    let count = findings
        .bitmono()
        .map_or(0, |b| b.anti_decompiler_types.count());
    if count > 0 {
        score.add(DetectionEvidence::StructuralPattern {
            description: format!(
                "{} nested <Module> types with AntiDecompiler attributes (Sealed|ExplicitLayout)",
                count
            ),
            confidence: 10,
        });
    }
}

/// Detects methods with malformed exception handlers (BitMono AntiDecompiler).
///
/// Uses `MethodBody::from_lenient()` which filters invalid exception handlers
/// during parsing. If any handlers were filtered (count > 0), the method had
/// garbage EH data — exactly what BitMono AntiDecompiler injects.
///
/// Confidence: +10 if any found.
fn detect_malformed_exception_handlers(
    assembly: &CilObject,
    score: &DetectionScore,
    findings: &mut DeobfuscationFindings,
) {
    let Some(tables) = assembly.tables() else {
        return;
    };
    let Some(method_table) = tables.table::<MethodDefRaw>() else {
        return;
    };
    let file = assembly.file();

    let mut malformed_count = 0usize;

    for row in method_table {
        if row.rva == 0 {
            continue;
        }

        let code_type = MethodImplCodeType::from_impl_flags(row.impl_flags);
        if code_type.contains(MethodImplCodeType::NATIVE)
            || code_type.contains(MethodImplCodeType::RUNTIME)
        {
            continue;
        }

        let Ok(offset) = file.rva_to_offset(row.rva as usize) else {
            continue;
        };
        let available = file.data().len().saturating_sub(offset);
        if available == 0 {
            continue;
        }

        let body_data = &file.data()[offset..offset + available];

        // Use lenient parsing: if any handlers were filtered out, they were invalid
        if let Ok((_, filtered)) = MethodBody::from_lenient(body_data) {
            if filtered > 0 {
                findings.init_bitmono().malformed_eh_methods.push(row.token);
                malformed_count += 1;
            }
        }
    }

    if malformed_count > 0 {
        score.add(DetectionEvidence::StructuralPattern {
            description: format!(
                "{} methods with malformed exception handlers (BitMono AntiDecompiler)",
                malformed_count
            ),
            confidence: 10,
        });
    }
}

/// Detects BitMono AntiDe4dot fake attributes.
///
/// Checks the CustomAttribute table for module-level attributes referencing TypeRefs
/// to known fake obfuscator assemblies (SmartAssembly, Xenocode, Goliath, Agile.NET,
/// Babel, etc.).
///
/// Confidence: +15 if found.
fn detect_antide4dot_attributes(
    assembly: &CilObject,
    score: &DetectionScore,
    findings: &mut DeobfuscationFindings,
) {
    let Some(tables) = assembly.tables() else {
        return;
    };
    let Some(strings) = assembly.strings() else {
        return;
    };
    let Some(custom_attr_table) = tables.table::<CustomAttributeRaw>() else {
        return;
    };
    let Some(memberref_table) = tables.table::<MemberRefRaw>() else {
        return;
    };
    let Some(typeref_table) = tables.table::<TypeRefRaw>() else {
        return;
    };

    // Fake obfuscator assembly type names used by BitMono's AntiDe4dot
    const FAKE_OBFUSCATOR_TYPES: &[&str] = &[
        "SmartAssembly",
        "Xenocode",
        "Goliath",
        "Dotfuscator",
        "Agile",
        "Babel",
        "Spices",
        "Eziriz",
        "MaxtoCode",
        "Salamander",
        "Reactor",
        "CodeWall",
        "DeepSea",
        "Skater",
        "Crypto",
        "Demeanor",
        "PostBuild",
        "TrinityObfuscator",
        "CliSecure",
        "ZYXDNGuarder",
        "Centos",
        "ConfusedBy",
        "NineRays",
        "EMyPID",
    ];

    let mut fake_attr_count = 0usize;

    for attr in custom_attr_table {
        // Only check module-level or assembly-level attributes
        let is_module_or_assembly =
            attr.parent.tag == TableId::Module || attr.parent.tag == TableId::Assembly;
        if !is_module_or_assembly {
            continue;
        }

        // Resolve the attribute's type name via MemberRef → TypeRef chain
        if attr.constructor.tag != TableId::MemberRef {
            continue;
        }
        let Some(memberref) = memberref_table.get(attr.constructor.row) else {
            continue;
        };
        if memberref.class.tag != TableId::TypeRef {
            continue;
        }
        let Some(typeref) = typeref_table.get(memberref.class.row) else {
            continue;
        };

        let type_name = strings.get(typeref.type_name as usize).ok();
        let type_namespace = strings.get(typeref.type_namespace as usize).ok();

        // A TypeRef with Module resolution scope is never legitimate for an
        // attribute type — real attributes resolve to external assemblies.
        // BitMono's AntiDe4dot injects attributes with garbage TypeRefs that
        // have Module scope and non-printable names.
        let has_module_scope = typeref.resolution_scope.tag == TableId::Module;

        if let Some(name) = type_name {
            let full_name = if let Some(ns) = type_namespace {
                format!("{ns}.{name}")
            } else {
                name.to_string()
            };

            // Check if this references a known fake obfuscator type
            let is_fake = FAKE_OBFUSCATOR_TYPES
                .iter()
                .any(|pattern| full_name.contains(pattern));

            // Also flag attributes with Module-scoped TypeRefs or garbage names
            let is_garbage =
                has_module_scope || name.chars().any(|c| c.is_ascii_control() || c == '\0');

            if is_fake || is_garbage {
                findings.marker_attribute_tokens.push(attr.token);
                fake_attr_count += 1;
            }
        } else if has_module_scope {
            // TypeRef name couldn't be resolved — flag it as fake
            findings.marker_attribute_tokens.push(attr.token);
            fake_attr_count += 1;
        }
    }

    if fake_attr_count > 0 {
        score.add(DetectionEvidence::StructuralPattern {
            description: format!(
                "{} BitMono AntiDe4dot fake obfuscator attributes",
                fake_attr_count
            ),
            confidence: 15,
        });
    }
}

/// Detects BitMono FullRenamer space-containing names.
///
/// BitMono's word-pool renaming produces names like `"HasPermission GetPlugins.Awake"`.
/// This is a weak signal since other tools might produce space-containing names.
///
/// Confidence: +5 if >= 5 space-containing names found.
fn detect_renamer_names(assembly: &CilObject, score: &DetectionScore) {
    let mut space_name_count = 0usize;

    for type_entry in assembly.types().iter() {
        let cil_type = type_entry.value();

        // Check type name
        if cil_type.name.contains(' ') {
            space_name_count += 1;
        }

        // Check method names
        for (_, method_ref) in cil_type.methods.iter() {
            if let Some(method) = method_ref.upgrade() {
                if method.name.contains(' ') {
                    space_name_count += 1;
                }
            }
        }
    }

    if space_name_count >= 5 {
        score.add(DetectionEvidence::StructuralPattern {
            description: format!(
                "{} space-containing names (BitMono FullRenamer)",
                space_name_count
            ),
            confidence: 5,
        });
    }
}

/// Resolves a metadata token to a type name string.
///
/// For MemberRef tokens, follows the class reference to get the declaring type name.
/// For TypeRef tokens, returns the type name directly.
fn resolve_type_name_for_token(assembly: &CilObject, token: Token) -> Option<String> {
    let tables = assembly.tables()?;
    let strings = assembly.strings()?;

    match token.table() {
        // MemberRef (0x0A)
        0x0A => {
            let memberref_table = tables.table::<MemberRefRaw>()?;
            let memberref = memberref_table.get(token.row())?;
            if memberref.class.tag == TableId::TypeRef {
                let typeref_table = tables.table::<TypeRefRaw>()?;
                let typeref = typeref_table.get(memberref.class.row)?;
                let name = strings.get(typeref.type_name as usize).ok()?;
                let ns = strings
                    .get(typeref.type_namespace as usize)
                    .ok()
                    .unwrap_or("");
                Some(format!("{ns}.{name}"))
            } else if memberref.class.tag == TableId::TypeDef {
                let typedef_table = tables.table::<TypeDefRaw>()?;
                let typedef = typedef_table.get(memberref.class.row)?;
                let name = strings.get(typedef.type_name as usize).ok()?;
                let ns = strings
                    .get(typedef.type_namespace as usize)
                    .ok()
                    .unwrap_or("");
                Some(format!("{ns}.{name}"))
            } else {
                None
            }
        }
        // TypeRef (0x01)
        0x01 => {
            let typeref_table = tables.table::<TypeRefRaw>()?;
            let typeref = typeref_table.get(token.row())?;
            let name = strings.get(typeref.type_name as usize).ok()?;
            let ns = strings
                .get(typeref.type_namespace as usize)
                .ok()
                .unwrap_or("");
            Some(format!("{ns}.{name}"))
        }
        // TypeDef (0x02)
        0x02 => {
            let typedef_table = tables.table::<TypeDefRaw>()?;
            let typedef = typedef_table.get(token.row())?;
            let name = strings.get(typedef.type_name as usize).ok()?;
            let ns = strings
                .get(typedef.type_namespace as usize)
                .ok()
                .unwrap_or("");
            Some(format!("{ns}.{name}"))
        }
        _ => None,
    }
}

/// Resolves a metadata token to a member name string.
///
/// Returns the member name (method name) for MemberRef tokens, or the type name
/// for TypeRef tokens. Used for pattern matching on call targets.
fn resolve_member_name(
    assembly: &CilObject,
    token: crate::metadata::token::Token,
) -> Option<String> {
    let tables = assembly.tables()?;
    let strings = assembly.strings()?;

    match token.table() {
        // MemberRef (0x0A)
        0x0A => {
            let memberref_table = tables.table::<MemberRefRaw>()?;
            let memberref = memberref_table.get(token.row())?;
            let name = strings.get(memberref.name as usize).ok()?;

            // Get the declaring type for full context
            if memberref.class.tag == TableId::TypeRef {
                let typeref_table = tables.table::<TypeRefRaw>()?;
                if let Some(typeref) = typeref_table.get(memberref.class.row) {
                    let type_name = strings.get(typeref.type_name as usize).ok().unwrap_or("");
                    let ns = strings
                        .get(typeref.type_namespace as usize)
                        .ok()
                        .unwrap_or("");
                    if ns.is_empty() {
                        return Some(format!("{type_name}.{name}"));
                    }
                    return Some(format!("{ns}.{type_name}.{name}"));
                }
            } else if memberref.class.tag == TableId::TypeDef {
                let typedef_table = tables.table::<TypeDefRaw>()?;
                if let Some(typedef) = typedef_table.get(memberref.class.row) {
                    let type_name = strings.get(typedef.type_name as usize).ok().unwrap_or("");
                    return Some(format!("{type_name}.{name}"));
                }
            }

            Some(name.to_string())
        }
        // MethodDef (0x06)
        0x06 => {
            let method = assembly.method(&token)?;
            Some(method.name.clone())
        }
        _ => None,
    }
}

/// Checks if a method has the characteristic BitMono decryptor signature:
/// static, returns `string`, takes 3 or more `byte[]` parameters.
fn method_matches_decryptor_signature(method: &crate::metadata::method::Method) -> bool {
    // Must return string
    if !matches!(method.signature.return_type.base, TypeSignature::String) {
        return false;
    }

    // Must have 3+ parameters, all byte[]
    if method.signature.params.len() < 3 {
        return false;
    }

    let byte_array_count = method
        .signature
        .params
        .iter()
        .filter(|p| {
            matches!(&p.base, TypeSignature::SzArray(arr) if matches!(*arr.base, TypeSignature::U1))
        })
        .count();

    byte_array_count >= 3
}

#[cfg(test)]
mod tests {
    use crate::{
        deobfuscation::{detection::DetectionScore, findings::DeobfuscationFindings},
        file::repair::RepairAction,
    };

    use super::score_pe_repairs;

    #[test]
    fn test_pe_signature_repair_scores_high() {
        let mut findings = DeobfuscationFindings::new();
        findings.pe_repairs = vec![RepairAction::PeSignature {
            original: 0x0001_4550,
            restored: 0x0000_4550,
        }];

        let score = DetectionScore::new();
        score_pe_repairs(&findings, &score);

        // PE signature alone gives 40
        assert!(
            score.score() >= 40,
            "PE signature repair should score >= 40, got {}",
            score.score()
        );
    }

    #[test]
    fn test_data_directory_repair_scores_high() {
        let mut findings = DeobfuscationFindings::new();
        findings.pe_repairs = vec![RepairAction::DataDirectoryCount {
            original: 0x13,
            restored: 0x10,
        }];

        let score = DetectionScore::new();
        score_pe_repairs(&findings, &score);

        assert!(
            score.score() >= 40,
            "Data directory count repair should score >= 40, got {}",
            score.score()
        );
    }

    #[test]
    fn test_clr_header_repair_scores() {
        let mut findings = DeobfuscationFindings::new();
        findings.pe_repairs = vec![RepairAction::ClrHeaderSize {
            original: 0,
            restored: 72,
        }];

        let score = DetectionScore::new();
        score_pe_repairs(&findings, &score);

        assert!(
            score.score() >= 30,
            "CLR header size repair should score >= 30, got {}",
            score.score()
        );
    }

    #[test]
    fn test_no_repairs_scores_zero() {
        let findings = DeobfuscationFindings::new();
        let score = DetectionScore::new();
        score_pe_repairs(&findings, &score);
        assert_eq!(score.score(), 0);
    }
}
