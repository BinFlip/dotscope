//! BitMono DotNetHook reversal.
//!
//! Reverses BitMono's DotNetHook protection, which redirects method calls through
//! dynamically-generated stubs.
//!
//! # Pattern
//!
//! DotNetHook creates a Hooking type with a `RedirectStub(int, int)` method that
//! patches method entry points at runtime. For each hooked call site, it creates:
//! 1. A **dummy method** in `<Module>` with a trivial body (just `ret`) and the
//!    same signature as the original called method.
//! 2. An **init method** in `<Module>` that calls `RedirectStub(dummy, target)`
//!    to patch the dummy's native code entry point at runtime.
//! 3. Replaces the original `call <target>` with `call <dummy>`.
//!
//! # Token Staleness Problem
//!
//! The `ldc.i4` operands in init methods store metadata tokens that were valid
//! at the time DotNetHook created them in-memory. However, AsmResolver reassigns
//! method tokens during PE serialization (methods are reordered by declaring type).
//! Since `ldc.i4` is a raw integer operand (not a metadata token reference),
//! these values are NOT updated — they become stale.
//!
//! # Reversal Strategy
//!
//! Instead of trusting the stale `ldc.i4` values directly, we:
//! 1. Identify dummy methods structurally (trivial bodies in `<Module>`)
//! 2. Extract stale token pairs from init methods for relative ordering
//! 3. Build a stale→final token bijection for dummies (sorted order matching)
//! 4. Compute the target token offset using unique-signature matching
//! 5. Apply the offset to all stale targets to get correct final tokens

use std::collections::HashMap;

use crate::{
    cilassembly::GeneratorConfig,
    compiler::EventLog,
    deobfuscation::findings::DeobfuscationFindings,
    metadata::{
        signatures::{SignatureMethod, TypeSignature},
        tables::{MemberRefRaw, MethodDefRaw, TableDataOwned, TableId},
        token::Token,
        validation::ValidationConfig,
    },
    CilObject, Error, Result,
};

/// A dummy→target method token mapping extracted from an init method.
struct HookMapping {
    /// The dummy method token (calls to this get redirected).
    dummy_token: u32,
    /// The real target method token (where calls should actually go).
    target_token: u32,
}

/// Reverses all DotNetHook redirections in the assembly.
///
/// Finds the hook infrastructure type, extracts the dummy→target mapping from
/// initialization methods, and replaces all call sites that target dummy methods
/// with direct calls to the real targets.
pub fn reverse_dotnethook(
    assembly: CilObject,
    findings: &mut DeobfuscationFindings,
    events: &mut EventLog,
) -> Result<CilObject> {
    let Some(bm) = findings.bitmono() else {
        return Ok(assembly);
    };
    if bm.dotnethook_count == 0 {
        return Ok(assembly);
    }

    // Step 1: Find the RedirectStub method token
    // Prefer the token identified during detection (signature-based, survives renaming)
    let redirect_stub_token = bm
        .dotnethook_redirect_stub
        .or_else(|| find_redirect_stub(&assembly));
    let Some(redirect_stub_token) = redirect_stub_token else {
        events
            .info("BitMono: DotNetHook infrastructure detected but RedirectStub method not found");
        return Ok(assembly);
    };

    events.info(format!(
        "BitMono: RedirectStub identified at token 0x{:08X}",
        redirect_stub_token.value(),
    ));

    // Step 2: Find init methods that call RedirectStub and extract mappings
    let (mappings, init_method_tokens, stale_correction_map) =
        extract_hook_mappings(&assembly, redirect_stub_token);

    if mappings.is_empty() {
        events.info("BitMono: no DotNetHook mappings found");
        return Ok(assembly);
    }

    events.info(format!(
        "BitMono: found {} DotNetHook redirect mappings",
        mappings.len()
    ));

    // Build the replacement map: dummy_token → target_token
    let redirect_map: HashMap<u32, u32> = mappings
        .iter()
        .map(|m| (m.dummy_token, m.target_token))
        .collect();

    // Step 3: Scan all methods for references to dummy method tokens.
    //
    // Three patterns to match:
    // (a) Direct calls: `call <dummy>` / `callvirt <dummy>` / `newobj <dummy>` — token is the instruction operand
    // (b) CallToCalli: `ldc.i4 <dummy_token>; ...; ResolveMethod; calli` — token is an i32 immediate
    //
    // When both DotNetHook and CallToCalli are active, the original `call <real>`
    // becomes `call <dummy>` (DotNetHook), then the call becomes a calli sequence
    // (CallToCalli) with the dummy token embedded as an ldc.i4 operand.
    // We must patch both patterns so that subsequent CalltocalliReversalPass
    // resolves to the real target.
    let mut patches: Vec<(Token, usize, usize, u32)> = Vec::new(); // (method_token, patch_start, patch_end, new_target)

    for method_entry in assembly.methods() {
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
                        patches.push((
                            method.token,
                            instr.offset as usize,
                            (instr.offset + instr.size) as usize,
                            real_target,
                        ));
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
            // dummy tokens, but ldc.i4 values are STALE tokens. A stale app row
            // can collide with a final dummy row, causing wrong redirects.
            if instr.mnemonic.starts_with("ldc.i4") {
                if let Some(val) = instr.get_i32_operand() {
                    let u = val as u32;
                    if (u >> 24) == 0x06 {
                        if let Some(&corrected) = stale_correction_map.get(&u) {
                            if corrected != u {
                                patches.push((
                                    method.token,
                                    instr.offset as usize,
                                    (instr.offset + instr.size) as usize,
                                    corrected,
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    if patches.is_empty() {
        events.info("BitMono: no DotNetHook call sites found to patch");
        return Ok(assembly);
    }

    events.info(format!(
        "BitMono: patching {} DotNetHook call sites",
        patches.len()
    ));

    // Step 4: Apply patches using CilAssembly
    let mut cil_assembly = assembly.into_assembly();

    // Group patches by method token
    let mut method_patches: HashMap<Token, Vec<(usize, usize, u32)>> = HashMap::new();
    for (method_token, start, end, target) in &patches {
        method_patches
            .entry(*method_token)
            .or_default()
            .push((*start, *end, *target));
    }

    for (method_token, patch_list) in &method_patches {
        let rid = method_token.row();
        #[allow(clippy::redundant_closure_for_method_calls)]
        let method_row = cil_assembly
            .view()
            .tables()
            .and_then(|t| t.table::<MethodDefRaw>())
            .and_then(|table| table.get(rid))
            .ok_or_else(|| Error::Deobfuscation(format!("MethodDef row {} not found", rid)))?;

        let method_rva = method_row.rva;
        if method_rva == 0 {
            continue;
        }

        let file_offset = cil_assembly
            .view()
            .file()
            .rva_to_offset(method_rva as usize)?;

        let file_data = cil_assembly.view().file().data();
        let Some((_header_size, mut body_bytes)) = super::read_method_body(file_data, file_offset)
        else {
            continue;
        };

        // Apply patches in reverse order to maintain offsets
        let mut sorted: Vec<&(usize, usize, u32)> = patch_list.iter().collect();
        sorted.sort_by(|a, b| b.0.cmp(&a.0));

        for (patch_start, _patch_end, new_target) in sorted {
            // instr.offset is the absolute file offset of the instruction.
            // body_bytes starts at file_offset. So the instruction is at
            // body_bytes[patch_start - file_offset].
            if *patch_start < file_offset {
                continue;
            }
            let body_offset = *patch_start - file_offset;

            // Instruction is 5 bytes: 1-byte opcode + 4-byte operand.
            // Works for call/callvirt (token operand) and ldc.i4 (i32 operand).
            if body_offset + 5 > body_bytes.len() {
                continue;
            }

            let token_bytes = new_target.to_le_bytes();
            body_bytes[body_offset + 1] = token_bytes[0];
            body_bytes[body_offset + 2] = token_bytes[1];
            body_bytes[body_offset + 3] = token_bytes[2];
            body_bytes[body_offset + 4] = token_bytes[3];
        }

        let placeholder_rva = cil_assembly.store_method_body(body_bytes);

        #[allow(clippy::redundant_closure_for_method_calls)]
        let existing_row = cil_assembly
            .view()
            .tables()
            .and_then(|t| t.table::<MethodDefRaw>())
            .and_then(|table| table.get(rid))
            .ok_or_else(|| {
                Error::Deobfuscation(format!("MethodDef row {} not found for update", rid))
            })?;

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

        cil_assembly.table_row_update(
            TableId::MethodDef,
            rid,
            TableDataOwned::MethodDef(updated_row),
        )?;
    }

    // Step 5: Mark init methods and dummy methods for cleanup
    for token in &init_method_tokens {
        findings.proxy_methods.push(*token);
    }
    for mapping in &mappings {
        // Mark dummy methods as proxy methods for cleanup
        findings.proxy_methods.push(Token::new(mapping.dummy_token));
    }

    events.info(format!(
        "BitMono: reversed {} DotNetHook redirections in {} methods",
        patches.len(),
        method_patches.len()
    ));

    let config = GeneratorConfig::default();
    cil_assembly.into_cilobject_with(ValidationConfig::analysis(), config)
}

/// Finds the `RedirectStub` method token in the assembly by signature.
///
/// Searches for a static void(int32, int32) method whose body contains
/// PrepareMethod/GetFunctionPointer calls. This approach works regardless
/// of whether FullRenamer has been applied.
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
        // Verify body references JIT hooking APIs
        let has_hook_api = method.instructions().any(|instr| {
            instr
                .get_token_operand()
                .and_then(|t| resolve_member_name_from_assembly(assembly, t))
                .is_some_and(|n| n.contains("PrepareMethod") || n.contains("GetFunctionPointer"))
        });
        if has_hook_api {
            return Some(method.token);
        }
    }

    None
}

/// Resolves a metadata token to a member name string for name matching.
///
/// Handles MemberRef (0x0A) and MethodDef (0x06) tokens.
fn resolve_member_name_from_assembly(assembly: &CilObject, token: Token) -> Option<String> {
    let tables = assembly.tables()?;
    let strings = assembly.strings()?;

    match token.table() {
        0x0A => {
            let memberref_table = tables.table::<MemberRefRaw>()?;
            let memberref = memberref_table.get(token.row())?;
            let name = strings.get(memberref.name as usize).ok()?;
            Some(name.to_string())
        }
        0x06 => {
            let method = assembly.method(&token)?;
            Some(method.name.clone())
        }
        _ => None,
    }
}

/// Extracts hook mappings from initialization methods with stale token correction.
///
/// The `ldc.i4` operands in init methods contain metadata tokens that were valid
/// at creation time but became stale after PE serialization reordered the MethodDef
/// table. This function resolves the stale tokens to correct final tokens by:
///
/// 1. Finding init methods (call RedirectStub) and extracting stale token pairs
/// 2. Finding dummy methods in `<Module>` (trivial body, static)
/// 3. Building a stale→final bijection for dummies via sorted order matching
/// 4. Building a stale→final bijection for ALL original app methods
/// 5. Producing correct final dummy→target mappings
///
/// Returns: (hook_mappings, init_method_tokens, stale_correction_map)
/// The stale_correction_map maps ALL stale MethodDef tokens (including those
/// not hooked by DotNetHook) to their correct final tokens, enabling correction
/// of stale CallToCalli tokens in the same pass.
fn extract_hook_mappings(
    assembly: &CilObject,
    redirect_stub_token: Token,
) -> (Vec<HookMapping>, Vec<Token>, HashMap<u32, u32>) {
    // Phase 1: Find init methods and extract stale (dummy, target) token pairs
    let mut stale_pairs: Vec<(u32, u32)> = Vec::new(); // (stale_dummy, stale_target)
    let mut init_tokens: Vec<Token> = Vec::new();

    let module_type_token = assembly.types().module_type().map(|m| m.token);
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
                            if let Some(name) = resolve_member_name_from_assembly(assembly, tok) {
                                if name.contains("PrepareMethod")
                                    || name.contains("GetFunctionPointer")
                                {
                                    has_hook_api = true;
                                }
                                if name.contains("Marshal") && name.contains("Write") {
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
        if !in_module || !method.is_static() || method.name == ".cctor" {
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
        // Fallback: counts don't match, use stale tokens as-is (old behavior)
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
    //
    // In the stale (in-memory) table, app methods occupy contiguous rows starting
    // after <Module>'s original methods. In the final PE, they're shifted by the
    // number of methods BitMono added to <Module> (dummies + inits + cctor).
    //
    // We determine this offset empirically: find a dummy whose signature uniquely
    // matches one non-<Module>/non-infrastructure method, then compute
    // offset = final_target_row - stale_target_row.
    let target_offset = compute_target_offset(
        assembly,
        &stale_to_final_dummy,
        &stale_pairs,
        module_type_token,
        &infra_tokens,
    );

    // Phase 5: Build stale correction map using the computed offset
    //
    // AsmResolver reorders the MethodDef table during PE serialization, placing
    // all <Module> methods (including added dummies/inits) first. This shifts all
    // non-<Module> methods forward by the number of methods added to <Module>.
    //
    // The stale tokens in ldc.i4 operands refer to the pre-serialization row numbers.
    // We apply the computed offset to map ANY stale row to its correct final row.
    // The range covers all possible original method rows: from 1 to the estimated
    // original method count (total methods minus added dummies/inits).
    let offset = target_offset.unwrap_or(0);

    let total_methods = assembly.methods().iter().count() as u32;
    // Original method count = total - (dummies + inits added by DotNetHook)
    // The offset itself equals the number of added methods, so:
    let original_count = if offset > 0 {
        (total_methods as i64 - offset) as u32
    } else {
        total_methods
    };

    // Build correction for all possible stale rows (1..=original_count)
    let mut stale_correction_map: HashMap<u32, u32> = (1..=original_count)
        .filter_map(|r| {
            let stale = 0x0600_0000 | r;
            let final_row = (r as i64 + offset) as u32;
            // Only include entries where the correction changes the token
            // and the final row is within the valid method table range
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
    // The ldc.i4 contains the dummy's STALE token (valid in-memory, not in the PE).
    // We need to map it all the way to the final real target.
    for mapping in &mappings {
        for (stale_dummy, final_dummy_val) in &stale_to_final_dummy {
            if *final_dummy_val == mapping.dummy_token {
                stale_correction_map.insert(*stale_dummy, mapping.target_token);
            }
        }
    }

    (mappings, init_tokens, stale_correction_map)
}

/// Checks if a method body is a DotNetHook dummy (trivial default-return body).
///
/// Dummies are created with an empty `CilMethodBody` that AsmResolver fills with
/// just `ret`. The body is never executed at runtime (native code is patched).
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

/// Computes the offset between stale target tokens and final target tokens.
///
/// Finds dummies whose signatures uniquely match one non-`<Module>` method.
/// From each match: `offset = final_original_row - stale_target_row`.
/// Uses the majority offset across all unique-signature matches to handle
/// potential non-uniform shifts (e.g., when BitMono inserts types between
/// original app types).
fn compute_target_offset(
    assembly: &CilObject,
    stale_to_final_dummy: &HashMap<u32, u32>,
    stale_pairs: &[(u32, u32)],
    module_type_token: Option<Token>,
    infra_tokens: &[Token],
) -> Option<i64> {
    // Build stale_dummy → stale_target lookup
    let stale_dummy_to_target: HashMap<u32, u32> =
        stale_pairs.iter().map(|(d, t)| (*d, *t)).collect();

    // Iterate in deterministic order (sorted by stale dummy token)
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

    // Return the majority offset (most common among unique-signature matches)
    offset_votes
        .into_iter()
        .max_by_key(|(_, count)| *count)
        .map(|(offset, _)| offset)
}

/// Compares two method signatures for structural equality.
///
/// Checks return type and all parameter types. Ignores calling convention
/// flags (has_this etc.) since DotNetHook copies the full signature blob
/// from the original method to the static dummy.
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

/// Checks if a MemberRef token points to the same method as RedirectStub.
///
/// Matches by declaring type: if the MemberRef's class points to the same
/// TypeDef that contains the identified RedirectStub MethodDef, and the
/// MemberRef has matching signature (void, 2 params), it's a match.
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

    // Match by declaring type: if the MemberRef's class points to the same
    // TypeDef that contains the identified RedirectStub MethodDef.
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
    use crate::metadata::token::Token;

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
        // TypeRef (0x01) and MemberRef (0x0A) tokens should not be treated as redirects
        let typeref_val: i32 = 0x0100_0005_u32 as i32;
        let memberref_val: i32 = 0x0A00_0003_u32 as i32;

        assert_ne!((typeref_val as u32) >> 24, 0x06);
        assert_ne!((memberref_val as u32) >> 24, 0x06);
    }
}
