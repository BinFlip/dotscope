//! BitMono DotNetHook detection and reversal technique.
//!
//! Detects and reverses BitMono's DotNetHook protection, which redirects method
//! calls through dynamically-generated stubs. The hook infrastructure type
//! contains methods referencing `PrepareMethod`, `GetFunctionPointer`,
//! `VirtualProtect` (JIT hooking setup) and `Marshal.Write*` (memory patching)
//! APIs. A `RedirectStub` method with signature `static void(int32, int32)`
//! patches method entry points at runtime.
//!
//! # Detection
//!
//! Scans all types for methods containing both JIT hook setup APIs and
//! `Marshal.Write*` calls. Also identifies the `RedirectStub` method by its
//! `static void(int32, int32)` signature combined with `PrepareMethod` /
//! `GetFunctionPointer` references.
//!
//! # Transform
//!
//! Reverses hook redirections by:
//! 1. Extracting stale dummy-to-target token pairs from init methods
//! 2. Identifying dummy methods in `<Module>` (trivial bodies like `ret` or
//!    `ldc.i4.0; ret`)
//! 3. Building a stale-to-final token bijection via sorted order matching
//!    (AsmResolver reorders MethodDef rows during PE serialization)
//! 4. Computing a target token offset using unique-signature matching
//! 5. Patching all `call <dummy>` and `ldc.i4 <stale_token>` instructions
//!    with corrected tokens via direct byte writes
//!
//! # Token Staleness
//!
//! The `ldc.i4` operands in init methods store metadata tokens that were valid
//! at the time DotNetHook created them in-memory. However, AsmResolver reassigns
//! method tokens during PE serialization (methods are reordered by declaring
//! type). Since `ldc.i4` is a raw integer operand (not a metadata token
//! reference), these values are NOT updated — they become stale.

use std::{any::Any, collections::HashMap};

use crate::{
    compiler::{EventKind, EventLog},
    deobfuscation::techniques::{
        Detection, Detections, Evidence, Technique, TechniqueCategory, WorkingAssembly,
    },
    metadata::{
        signatures::{SignatureMethod, TypeSignature},
        tables::{MemberRefRaw, TableId},
        token::Token,
        typesystem::wellknown,
    },
    CilObject, Result,
};

/// Findings from BitMono DotNetHook detection.
#[derive(Debug)]
pub struct HookFindings {
    /// Token of the type containing hook infrastructure (PrepareMethod + Marshal.Write).
    pub infrastructure_type: Option<Token>,
    /// Token of the `RedirectStub` method: `static void(int32, int32)`.
    pub redirect_stub: Option<Token>,
    /// Number of hook redirect pairs detected.
    pub hook_count: usize,
    /// Dummy method tokens in `<Module>` (trivial bodies used as call targets).
    pub dummy_methods: Vec<Token>,
    /// Init method tokens in `<Module>` (methods that call RedirectStub to set up hooks).
    pub init_methods: Vec<Token>,
}

/// Detects and reverses BitMono's DotNetHook method redirection.
///
/// DotNetHook replaces direct `call <target>` instructions with calls to dummy
/// methods whose native entry points are patched at runtime to jump to the real
/// targets. Detection identifies the infrastructure type by scanning for
/// `PrepareMethod` + `Marshal.Write*` API references, and the `RedirectStub`
/// by its `static void(int32, int32)` signature.
pub struct BitMonoHooks;

impl Technique for BitMonoHooks {
    fn id(&self) -> &'static str {
        "bitmono.hooks"
    }

    fn name(&self) -> &'static str {
        "BitMono DotNetHook Reversal"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Protection
    }

    fn detect(&self, assembly: &CilObject) -> Detection {
        let mut infrastructure_type = None;
        let mut redirect_stub = None;
        let mut hook_count = 0usize;

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
                        if let Some(name) = assembly.resolve_method_name(token) {
                            if name.contains("PrepareMethod")
                                || name.contains("GetFunctionPointer")
                                || name.contains("VirtualProtect")
                                || name.contains("mprotect")
                            {
                                has_jit_hook_setup = true;
                            }
                        }
                        if let Some(member) = assembly.member_ref(&token) {
                            if member.name.contains("Write")
                                && member
                                    .declaredby
                                    .fullname()
                                    .is_some_and(|t| t.contains("Marshal"))
                            {
                                has_marshal_write = true;
                            }
                        }
                    }
                }
            }

            if has_jit_hook_setup && has_marshal_write {
                hook_count += 1;
                infrastructure_type = Some(cil_type.token);

                // Identify the RedirectStub method by signature: static void(int32, int32).
                // This approach works even when FullRenamer has renamed all method names.
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
                            .and_then(|t| assembly.resolve_method_name(t))
                            .is_some_and(|n| {
                                n.contains("PrepareMethod") || n.contains("GetFunctionPointer")
                            })
                    });
                    if has_hook_api {
                        redirect_stub = Some(method.token);
                        break;
                    }
                }

                // Only one DotNetHook infrastructure type expected
                break;
            }
        }

        if hook_count == 0 {
            return Detection::new_empty();
        }

        // Identify dummy methods (trivial bodies in <Module>) and init methods
        // (call RedirectStub) for cleanup. These are in <Module>, not the
        // infrastructure type, so they must be explicitly marked for removal.
        let mut dummy_methods = Vec::new();
        let mut init_methods = Vec::new();
        let module_type_token = assembly.types().module_type().map(|m| m.token);

        if let Some(stub_token) = redirect_stub {
            // Find dummy methods in <Module>: static, trivial body
            for method_entry in assembly.methods() {
                let method = method_entry.value();
                let in_module = method
                    .declaring_type_rc()
                    .map(|dt| Some(dt.token) == module_type_token)
                    .unwrap_or(false);
                if !in_module || !method.is_static() || method.name == wellknown::members::CCTOR {
                    continue;
                }
                let instrs: Vec<_> = method.instructions().collect();
                if is_dummy_body(&instrs) {
                    dummy_methods.push(method.token);
                }
            }

            // Find init methods: methods that call RedirectStub
            for method_entry in assembly.methods() {
                let method = method_entry.value();
                for instr in method.instructions() {
                    if instr.mnemonic == "call" {
                        if let Some(call_target) = instr.get_token_operand() {
                            let is_redirect = call_target == stub_token
                                || is_redirect_stub_memberref(assembly, call_target, stub_token);
                            if is_redirect && !init_methods.contains(&method.token) {
                                init_methods.push(method.token);
                            }
                        }
                    }
                }
            }
        }

        let mut evidence = vec![Evidence::Structural(
            "BitMono DotNetHook infrastructure (PrepareMethod + Marshal.Write)".to_string(),
        )];

        if redirect_stub.is_some() {
            evidence.push(Evidence::Structural(
                "RedirectStub identified: static void(int32, int32)".to_string(),
            ));
        }

        let findings = HookFindings {
            infrastructure_type,
            redirect_stub,
            hook_count,
            dummy_methods: dummy_methods.clone(),
            init_methods: init_methods.clone(),
        };

        let mut detection = Detection::new_detected(
            evidence,
            Some(Box::new(findings) as Box<dyn Any + Send + Sync>),
        );

        // Mark infrastructure type for cleanup so post-deobfuscation
        // re-detection doesn't re-trigger.
        if let Some(infra_token) = infrastructure_type {
            detection.cleanup_mut().add_type(infra_token);
        }

        // Mark dummy methods and init methods for cleanup.
        // These live in <Module> and won't cascade from the infrastructure type.
        detection.cleanup_mut().add_methods(dummy_methods);
        detection.cleanup_mut().add_methods(init_methods);

        detection
    }

    fn byte_transform(
        &self,
        assembly: &mut WorkingAssembly,
        detection: &Detection,
        _detections: &Detections,
    ) -> Option<Result<EventLog>> {
        let events = EventLog::new();

        let Some(findings) = detection.findings::<HookFindings>() else {
            return Some(Ok(events));
        };

        let co = match assembly.cilobject() {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };

        let redirect_stub_token = match findings.redirect_stub {
            Some(token) => token,
            None => {
                // Try finding the RedirectStub again from the current assembly view
                match find_redirect_stub(co) {
                    Some(token) => token,
                    None => {
                        events.record(EventKind::ArtifactRemoved).message(
                            "DotNetHook: infrastructure detected but RedirectStub not found"
                                .to_string(),
                        );
                        return Some(Ok(events));
                    }
                }
            }
        };

        // Extract hook mappings with stale token correction
        let view = co;
        let (mappings, _init_tokens, stale_correction_map) =
            extract_hook_mappings(view, redirect_stub_token);

        if mappings.is_empty() {
            events
                .record(EventKind::ArtifactRemoved)
                .message("DotNetHook: no redirect mappings found".to_string());
            return Some(Ok(events));
        }

        // Build the redirect map: dummy_token → target_token
        let redirect_map: HashMap<u32, u32> = mappings
            .iter()
            .map(|m| (m.dummy_token, m.target_token))
            .collect();

        // Scan all methods for references to dummy method tokens and build patches.
        //
        // Two patterns:
        // (a) Direct calls: call/callvirt/newobj <dummy> — token is the instruction operand
        // (b) CallToCalli: ldc.i4 <stale_dummy_token> — token is an i32 immediate
        //
        // When both DotNetHook and CallToCalli are active, the original `call <real>`
        // becomes `call <dummy>` (DotNetHook), then the call becomes a calli sequence
        // (CallToCalli) with the dummy token embedded as an ldc.i4 operand.
        let mut patches: Vec<(u64, u32)> = Vec::new(); // (file_offset_of_operand, new_token)

        for method_entry in view.methods() {
            let method = method_entry.value();
            for instr in method.instructions() {
                // Pattern (a): direct call/callvirt/newobj with dummy token operand
                if instr.mnemonic == "call"
                    || instr.mnemonic == "callvirt"
                    || instr.mnemonic == "newobj"
                {
                    if let Some(call_target) = instr.get_token_operand() {
                        let raw_token = call_target.value();
                        if let Some(&real_target) = redirect_map.get(&raw_token) {
                            // Token operand is the last 4 bytes of the instruction
                            patches.push((instr.offset + instr.size - 4, real_target));
                        }
                    }
                    continue;
                }

                // Pattern (b): ldc.i4 with a stale MethodDef token value
                //
                // All ldc.i4 tokens in calli patterns are stale (from the in-memory
                // assembly before PE serialization). The stale_correction_map handles:
                // - Stale app method tokens (CallToCalli ran first, no DotNetHook hook)
                // - Stale dummy tokens (DotNetHook ran first, then CallToCalli)
                //
                // We do NOT use redirect_map here: redirect_map is indexed by FINAL
                // dummy tokens, but ldc.i4 values are STALE tokens.
                if instr.mnemonic == "ldc.i4" {
                    if let Some(val) = instr.get_i32_operand() {
                        let u = val as u32;
                        if (u >> 24) == 0x06 {
                            if let Some(&corrected) = stale_correction_map.get(&u) {
                                if corrected != u {
                                    // ldc.i4 is 5 bytes: 0x20 + i32 operand
                                    patches.push((instr.offset + 1, corrected));
                                }
                            }
                        }
                    }
                }
            }
        }

        if patches.is_empty() {
            events
                .record(EventKind::ArtifactRemoved)
                .message("DotNetHook: no call sites found to patch".to_string());
            return Some(Ok(events));
        }

        // Apply patches: write corrected 4-byte token values at each operand offset
        for &(operand_offset, new_token) in &patches {
            if let Err(e) = assembly.write_le::<u32>(operand_offset as usize, new_token) {
                return Some(Err(e));
            }
        }

        let patch_count = patches.len();
        let mapping_count = mappings.len();
        events.record(EventKind::ArtifactRemoved).message(format!(
            "Reversed {mapping_count} DotNetHook redirections, patched {patch_count} call sites",
        ));

        Some(Ok(events))
    }

    fn requires_regeneration(&self) -> bool {
        true
    }
}

/// Finds the `RedirectStub` method token by signature and body content.
///
/// Scans all methods for a `static void(int32, int32)` whose body references
/// `PrepareMethod` or `GetFunctionPointer`. This signature-based search is
/// robust to FullRenamer obfuscation where the method name is gone.
///
/// # Arguments
///
/// * `assembly` - The assembly to scan.
///
/// # Returns
///
/// `Some(token)` of the first matching `RedirectStub` method, or `None` if
/// no method matches the signature and body criteria.
fn find_redirect_stub(assembly: &CilObject) -> Option<Token> {
    for method_entry in assembly.methods() {
        let method = method_entry.value();
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
        let has_hook_api = method.instructions().any(|instr| {
            instr
                .get_token_operand()
                .and_then(|t| assembly.resolve_method_name(t))
                .is_some_and(|n| n.contains("PrepareMethod") || n.contains("GetFunctionPointer"))
        });
        if has_hook_api {
            return Some(method.token);
        }
    }
    None
}

/// A dummy→target method token mapping extracted from an init method.
struct HookMapping {
    /// The dummy method token (calls to this get redirected).
    dummy_token: u32,
    /// The real target method token (where calls should actually go).
    target_token: u32,
}

/// Extracts hook mappings from initialization methods with stale token correction.
///
/// The `ldc.i4` operands in init methods contain metadata tokens that were valid
/// at creation time but became stale after PE serialization reordered the MethodDef
/// table. Resolves stale tokens to correct final tokens via the following steps:
///
/// 1. Finding init methods (callers of `RedirectStub`) and extracting stale token pairs
/// 2. Finding dummy methods in `<Module>` (trivial body, static)
/// 3. Building a stale→final bijection for dummies via sorted order matching
/// 4. Computing a target token offset via unique-signature matching
/// 5. Producing correct final dummy→target mappings
///
/// # Arguments
///
/// * `assembly` - The assembly to scan for init methods and dummy methods.
/// * `redirect_stub_token` - Token of the `RedirectStub` method, used to identify
///   init methods that set up hooks by calling it.
///
/// # Returns
///
/// A tuple of `(hook_mappings, init_method_tokens, stale_correction_map)`:
/// - `hook_mappings`: Final dummy→target token pairs ready for patching.
/// - `init_method_tokens`: Tokens of init methods, for cleanup.
/// - `stale_correction_map`: Stale→final token map for `ldc.i4` patching.
///   Empty if the correction computation failed (counts mismatch).
fn extract_hook_mappings(
    assembly: &CilObject,
    redirect_stub_token: Token,
) -> (Vec<HookMapping>, Vec<Token>, HashMap<u32, u32>) {
    // Phase 1: Find init methods and extract stale (dummy, target) token pairs
    let mut stale_pairs: Vec<(u32, u32)> = Vec::new();
    let mut init_tokens: Vec<Token> = Vec::new();

    let module_type_token = assembly.types().module_type().map(|m| m.token);

    // Identify infrastructure type tokens (types with hook setup APIs)
    let infra_tokens: Vec<Token> = assembly
        .types()
        .iter()
        .filter(|entry| {
            let t = entry.value();
            let mut has_hook_api = false;
            let mut has_marshal = false;
            for (_, mr) in t.methods.iter() {
                if let Some(m) = mr.upgrade() {
                    for instr in m.instructions() {
                        if let Some(tok) = instr.get_token_operand() {
                            if let Some(name) = assembly.resolve_method_name(tok) {
                                if name.contains("PrepareMethod")
                                    || name.contains("GetFunctionPointer")
                                {
                                    has_hook_api = true;
                                }
                            }
                            if let Some(member) = assembly.member_ref(&tok) {
                                if member.name.contains("Write")
                                    && member
                                        .declaredby
                                        .fullname()
                                        .is_some_and(|t| t.contains("Marshal"))
                                {
                                    has_marshal = true;
                                }
                            }
                        }
                    }
                }
            }
            has_hook_api && has_marshal
        })
        .map(|entry| entry.value().token)
        .collect();

    // Scan all methods for calls to RedirectStub and extract stale token pairs
    for method_entry in assembly.methods() {
        let method = method_entry.value();
        let instructions: Vec<_> = method.instructions().collect();

        for (i, instr) in instructions.iter().enumerate() {
            if instr.mnemonic != "call" {
                continue;
            }
            let Some(call_target) = instr.get_token_operand() else {
                continue;
            };
            let is_redirect_call = call_target == redirect_stub_token
                || is_redirect_stub_memberref(assembly, call_target, redirect_stub_token);
            if !is_redirect_call || i < 2 {
                continue;
            }

            let arg1 = instructions[i - 2]
                .mnemonic
                .starts_with("ldc.i4")
                .then(|| instructions[i - 2].get_i32_operand())
                .flatten();
            let arg2 = instructions[i - 1]
                .mnemonic
                .starts_with("ldc.i4")
                .then(|| instructions[i - 1].get_i32_operand())
                .flatten();

            if let (Some(a1), Some(a2)) = (arg1, arg2) {
                let d = a1 as u32;
                let t = a2 as u32;
                if (d >> 24) == 0x06 && (t >> 24) == 0x06 {
                    stale_pairs.push((d, t));
                    if !init_tokens.contains(&method.token) {
                        init_tokens.push(method.token);
                    }
                }
            }
        }
    }

    if stale_pairs.is_empty() {
        return (Vec::new(), Vec::new(), HashMap::new());
    }

    // Phase 2: Find dummy methods in <Module> — trivial body (just `ret`), static
    let mut dummy_final_tokens: Vec<Token> = Vec::new();

    for method_entry in assembly.methods() {
        let method = method_entry.value();
        let in_module = method
            .declaring_type_rc()
            .map(|dt| Some(dt.token) == module_type_token)
            .unwrap_or(false);
        if !in_module || !method.is_static() || method.name == wellknown::members::CCTOR {
            continue;
        }
        let instrs: Vec<_> = method.instructions().collect();
        if is_dummy_body(&instrs) {
            dummy_final_tokens.push(method.token);
        }
    }

    // Phase 3: Build stale→final dummy bijection via sorted order matching
    let mut stale_dummy_sorted: Vec<u32> = stale_pairs.iter().map(|(sd, _)| *sd).collect();
    stale_dummy_sorted.sort();
    stale_dummy_sorted.dedup();

    dummy_final_tokens.sort_by_key(|t| t.row());

    if stale_dummy_sorted.len() != dummy_final_tokens.len() {
        // Fallback: counts don't match, use stale tokens as-is
        let mappings = stale_pairs
            .iter()
            .map(|(d, t)| HookMapping {
                dummy_token: *d,
                target_token: *t,
            })
            .collect();
        return (mappings, init_tokens, HashMap::new());
    }

    let stale_to_final_dummy: HashMap<u32, u32> = stale_dummy_sorted
        .iter()
        .zip(dummy_final_tokens.iter())
        .map(|(s, f)| (*s, f.value()))
        .collect();

    // Phase 4: Compute the target token offset
    let target_offset = compute_target_offset(
        assembly,
        &stale_to_final_dummy,
        &stale_pairs,
        module_type_token,
        &infra_tokens,
    );

    // Phase 5: Build stale correction map
    let offset = target_offset.unwrap_or(0);
    let total_methods = assembly.methods().iter().count() as u32;
    let original_count = if offset > 0 {
        (total_methods as i64 - offset) as u32
    } else {
        total_methods
    };

    let mut stale_correction_map: HashMap<u32, u32> = (1..=original_count)
        .filter_map(|r| {
            let stale = 0x0600_0000 | r;
            let final_row = (r as i64 + offset) as u32;
            if final_row != r && final_row >= 1 && final_row <= total_methods {
                Some((stale, 0x0600_0000 | final_row))
            } else {
                None
            }
        })
        .collect();

    // Build hook mappings using the stale correction map
    let mappings: Vec<HookMapping> = stale_pairs
        .iter()
        .map(|(stale_dummy, stale_target)| {
            let final_dummy = stale_to_final_dummy
                .get(stale_dummy)
                .copied()
                .unwrap_or(*stale_dummy);
            let final_target = stale_correction_map
                .get(stale_target)
                .copied()
                .unwrap_or(*stale_target);
            HookMapping {
                dummy_token: final_dummy,
                target_token: final_target,
            }
        })
        .collect();

    // Add stale dummy → final target mappings to the correction map.
    //
    // When both DotNetHook and CallToCalli are active, some calls go through:
    //   call <target> → call <dummy> (DotNetHook) → ldc.i4 <stale_dummy>; calli (CallToCalli)
    // The ldc.i4 contains the dummy's STALE token. Map it to the final real target.
    for mapping in &mappings {
        for (stale_dummy, final_dummy_val) in &stale_to_final_dummy {
            if *final_dummy_val == mapping.dummy_token {
                stale_correction_map.insert(*stale_dummy, mapping.target_token);
            }
        }
    }

    (mappings, init_tokens, stale_correction_map)
}

/// Returns `true` if a method body matches the DotNetHook dummy pattern.
///
/// Dummies are created with an empty `CilMethodBody` that AsmResolver fills with
/// just `ret` (void return) or a simple default-value push followed by `ret`
/// (non-void return). Their native code is patched at runtime so the body is
/// never executed.
///
/// # Arguments
///
/// * `instructions` - Slice of instruction references from the method body.
///
/// # Returns
///
/// `true` if the body matches one of the recognized dummy patterns:
/// - 1 instruction: `ret`
/// - 2 instructions: `ldc.*` or `ldnull`, then `ret`
/// - 3 instructions: `ldc.*` + `conv.*` + `ret`, or `ldloca` + `initobj` + `ret`
fn is_dummy_body(instructions: &[&crate::assembly::Instruction]) -> bool {
    if instructions.is_empty() {
        return false;
    }
    let last = instructions.last().unwrap();
    if last.mnemonic != "ret" {
        return false;
    }
    match instructions.len() {
        1 => true, // just ret (void or stack-underflow dummy)
        2 => {
            let m = instructions[0].mnemonic;
            m.starts_with("ldc.") || m == "ldnull"
        }
        3 => {
            let m0 = instructions[0].mnemonic;
            let m1 = instructions[1].mnemonic;
            // ldc.i4.0 + conv.i8 + ret (int64 return)
            // ldloca.s + initobj + ret (value type return — rare)
            (m0.starts_with("ldc.") && m1.starts_with("conv."))
                || (m0.starts_with("ldloca") && m1 == "initobj")
        }
        _ => false,
    }
}

/// Computes the offset between stale target tokens and their final counterparts.
///
/// For each dummy method whose signature uniquely matches exactly one
/// non-`<Module>`, non-infrastructure method, computes:
/// `offset = final_original_row - stale_target_row`.
/// Returns the majority-vote offset across all such matches, which is the
/// global correction to apply to all stale `0x06xxxxxx` token values.
///
/// # Arguments
///
/// * `assembly` - The assembly to scan for candidate target methods.
/// * `stale_to_final_dummy` - Map of stale dummy token → final dummy token.
/// * `stale_pairs` - Raw `(stale_dummy, stale_target)` pairs from init methods.
/// * `module_type_token` - Token of `<Module>`, used to exclude module methods.
/// * `infra_tokens` - Tokens of DotNetHook infrastructure types, also excluded.
///
/// # Returns
///
/// `Some(offset)` if a majority offset was found, or `None` if no unique-signature
/// matches were available.
fn compute_target_offset(
    assembly: &CilObject,
    stale_to_final_dummy: &HashMap<u32, u32>,
    stale_pairs: &[(u32, u32)],
    module_type_token: Option<Token>,
    infra_tokens: &[Token],
) -> Option<i64> {
    let stale_dummy_to_target: HashMap<u32, u32> =
        stale_pairs.iter().map(|(d, t)| (*d, *t)).collect();

    let mut sorted_entries: Vec<(&u32, &u32)> = stale_to_final_dummy.iter().collect();
    sorted_entries.sort_by_key(|(k, _)| *k);

    let mut offset_votes: HashMap<i64, usize> = HashMap::new();

    for (stale_dummy, final_dummy_val) in sorted_entries {
        let final_dummy_token = Token::new(*final_dummy_val);
        let Some(dummy_method) = assembly.method(&final_dummy_token) else {
            continue;
        };

        // Find non-<Module>, non-infrastructure methods with matching signature
        let mut candidates: Vec<Token> = Vec::new();
        for method_entry in assembly.methods() {
            let method = method_entry.value();
            if let Some(dt) = method.declaring_type_rc() {
                if Some(dt.token) == module_type_token {
                    continue;
                }
                if infra_tokens.contains(&dt.token) {
                    continue;
                }
            }
            if signatures_match(&method.signature, &dummy_method.signature) {
                candidates.push(method.token);
            }
        }

        let Some(&stale_target) = stale_dummy_to_target.get(stale_dummy) else {
            continue;
        };
        let stale_row = (stale_target & 0x00FF_FFFF) as i64;

        if candidates.len() == 1 {
            let final_row = candidates[0].row() as i64;
            let offset = final_row - stale_row;
            *offset_votes.entry(offset).or_insert(0) += 1;
        }
    }

    offset_votes
        .into_iter()
        .max_by_key(|(_, count)| *count)
        .map(|(offset, _)| offset)
}

/// Returns `true` if two method signatures have the same return type and parameters.
///
/// Ignores calling convention flags since DotNetHook copies the full signature
/// blob from the original method to the static dummy, which may alter flags
/// without changing the structural shape.
///
/// # Arguments
///
/// * `a` - First method signature.
/// * `b` - Second method signature.
///
/// # Returns
///
/// `true` if both signatures have identical return type base and all parameter
/// type bases match pairwise.
fn signatures_match(a: &SignatureMethod, b: &SignatureMethod) -> bool {
    if a.return_type.base != b.return_type.base {
        return false;
    }
    if a.params.len() != b.params.len() {
        return false;
    }
    a.params
        .iter()
        .zip(b.params.iter())
        .all(|(pa, pb)| pa.base == pb.base)
}

/// Returns `true` if `token` is a `MemberRef` that resolves to the same declaring
/// type as `redirect_stub_token`.
///
/// Used to handle cross-assembly references where the caller uses a `MemberRef`
/// (table `0x0A`) rather than a direct `MethodDef` token. Matches by declaring
/// type: if the `MemberRef`'s class points to the same `TypeDef` row that
/// contains the identified `RedirectStub`.
///
/// # Arguments
///
/// * `assembly` - The assembly containing both tokens.
/// * `token` - Candidate token to test (must be a `MemberRef`, table `0x0A`).
/// * `redirect_stub_token` - The known `RedirectStub` `MethodDef` token.
///
/// # Returns
///
/// `true` if `token` is a `MemberRef` whose class is the `TypeDef` that
/// declares `redirect_stub_token`, `false` otherwise.
fn is_redirect_stub_memberref(
    assembly: &CilObject,
    token: Token,
    redirect_stub_token: Token,
) -> bool {
    if token.table() != 0x0A {
        return false;
    }

    let Some(tables) = assembly.tables() else {
        return false;
    };
    let Some(memberref_table) = tables.table::<MemberRefRaw>() else {
        return false;
    };
    let Some(memberref) = memberref_table.get(token.row()) else {
        return false;
    };

    if memberref.class.tag == TableId::TypeDef {
        if let Some(stub_method) = assembly.method(&redirect_stub_token) {
            if let Some(stub_type) = stub_method.declaring_type_rc() {
                return memberref.class.row == stub_type.token.row();
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use crate::test::helpers::load_sample;
    use crate::{deobfuscation::techniques::Technique, metadata::token::Token};

    #[test]
    fn test_hook_mapping_token_extraction() {
        // Verify that i32 values from ldc.i4 correctly map to MethodDef tokens
        let dummy_i32: i32 = 0x0600_0010_u32 as i32;
        let target_i32: i32 = 0x0600_0020_u32 as i32;

        let dummy_u32 = dummy_i32 as u32;
        let target_u32 = target_i32 as u32;

        assert_eq!(dummy_u32 >> 24, 0x06, "Dummy should be MethodDef");
        assert_eq!(target_u32 >> 24, 0x06, "Target should be MethodDef");

        let dummy_token = Token::new(dummy_u32);
        let target_token = Token::new(target_u32);

        assert_eq!(dummy_token.row(), 0x10);
        assert_eq!(target_token.row(), 0x20);
    }

    #[test]
    fn test_non_methoddef_tokens_rejected() {
        let typeref_val: i32 = 0x0100_0005_u32 as i32;
        let memberref_val: i32 = 0x0A00_0003_u32 as i32;

        assert_ne!((typeref_val as u32) >> 24, 0x06);
        assert_ne!((memberref_val as u32) >> 24, 0x06);
    }

    #[test]
    fn test_detect_positive() {
        let assembly = load_sample("tests/samples/packers/bitmono/0.39.0/bitmono_dotnethook.exe");

        let technique = super::BitMonoHooks;
        let detection = technique.detect(&assembly);

        assert!(
            detection.is_detected(),
            "BitMonoHooks should detect DotNetHook infrastructure in bitmono_dotnethook.exe"
        );
        assert!(
            !detection.evidence().is_empty(),
            "Detection should include evidence"
        );
    }

    #[test]
    fn test_detect_negative() {
        let assembly = load_sample("tests/samples/packers/confuserex/1.6.0/original.exe");

        let technique = super::BitMonoHooks;
        let detection = technique.detect(&assembly);

        assert!(
            !detection.is_detected(),
            "BitMonoHooks should not detect DotNetHook in a non-BitMono assembly"
        );
    }
}
