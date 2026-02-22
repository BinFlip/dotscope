//! BitMono StringsEncryption reversal.
//!
//! Implements static AES decryption of strings encrypted by BitMono's StringsEncryption
//! protection. Unlike ConfuserEx (which uses emulation), BitMono's encryption is fully
//! static — the key material is embedded as FieldRVA data and the algorithm is standard
//! AES-256-CBC with PBKDF2-HMAC-SHA1.
//!
//! # Algorithm
//!
//! Each string literal is replaced with a 4-instruction sequence:
//! ```text
//! ldsfld     byte[] <encrypted_data_field>     // per-string FieldRVA data
//! ldsfld     byte[] <salt_field>               // shared 8-byte salt
//! ldsfld     byte[] <crypt_key_field>          // shared 8-byte key
//! call       string Decrypt(byte[], byte[], byte[])
//! ```
//!
//! # Two-Phase Design
//!
//! **Phase A — `prepare_string_decryption()`** (byte-level, runs before SSA):
//! - Tags infrastructure fields in findings (encrypted data, salt, key fields)
//! - Stubs decryptor method bodies with `ldnull; ret` to prevent SSA construction
//!   failures on malformed exception handlers
//!
//! **Phase B — `StringDecryptionPass`** (SSA pass, runs AFTER `CalltocalliReversalPass`):
//! - Finds `Call` to decryptor methods in SSA blocks
//! - Traces each site's `LoadStaticField` args to identify its specific encrypted
//!   data, salt, and key fields
//! - Derives AES key material per (salt, key) pair (cached for efficiency)
//! - Decrypts only fields actually referenced as decryptor arguments
//! - Replaces `Call` with `DecryptedString` constant, NOPs intermediate instructions

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex, OnceLock},
};

use aes::Aes256;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use cbc::Decryptor;

use crate::{
    analysis::{ConstValue, SsaFunction, SsaOp, SsaVarId},
    cilassembly::GeneratorConfig,
    compiler::{CompilerContext, EventKind, EventLog, ModificationScope, SsaPass},
    deobfuscation::{findings::DeobfuscationFindings, obfuscators::utils},
    metadata::{
        tables::{FieldRaw, FieldRvaRaw, MethodDefRaw, TableDataOwned, TableId, TypeDefRaw},
        token::Token,
        validation::ValidationConfig,
    },
    CilObject, Error, Result,
};

/// Cached AES key material: `(derived_key, derived_iv)` per `(salt_token, key_token)` pair.
type KeyCache = HashMap<(Token, Token), (Vec<u8>, Vec<u8>)>;

/// A pending string replacement: `(call_idx, call_dest, ldsfld_locations, decrypted_string)`.
type StringReplacement = (usize, SsaVarId, [(usize, usize); 3], String);

// ============================================================================
// Phase A: Byte-level preparation (runs in deobfuscate())
// ============================================================================

/// A call site where the decryptor method is invoked (byte-level analysis).
struct CallSite {
    /// Field RID of the per-string encrypted data (1st ldsfld).
    encrypted_field_rid: u32,
    /// Field RID of the shared salt (2nd ldsfld).
    salt_field_rid: u32,
    /// Field RID of the shared crypt key (3rd ldsfld).
    key_field_rid: u32,
}

/// Prepares the assembly for SSA-based string decryption.
///
/// This byte-level phase does NOT decrypt or patch anything. It:
/// 1. Collects call sites to identify infrastructure field tokens
/// 2. Tags encrypted data, salt, and key fields in findings
/// 3. Stubs decryptor method bodies with `ldnull; ret` to avoid SSA
///    construction failures on malformed exception handlers
///
/// Actual decryption happens in [`StringDecryptionPass`] which runs
/// after `CalltocalliReversalPass` restores `call` instructions.
pub fn prepare_string_decryption(
    assembly: CilObject,
    findings: &mut DeobfuscationFindings,
    events: &mut EventLog,
) -> Result<CilObject> {
    if findings.decryptor_methods.count() == 0 {
        return Ok(assembly);
    }

    let decryptor_tokens: Vec<Token> = findings.decryptor_methods.iter().map(|(_, t)| *t).collect();

    // Collect call sites to identify infrastructure fields.
    // When DotNetHook was active, also search for calli patterns (DotNetHook + CallToCalli combo).
    let search_calli = findings
        .bitmono()
        .map_or(false, |bm| bm.dotnethook_count > 0);
    let call_sites = collect_call_sites(&assembly, &decryptor_tokens, search_calli)?;

    // Tag infrastructure fields (encrypted data, salt, key)
    for site in &call_sites {
        findings
            .infrastructure_fields
            .push(Token::new(site.encrypted_field_rid | 0x0400_0000));
    }
    if let Some(first) = call_sites.first() {
        findings
            .infrastructure_fields
            .push(Token::new(first.salt_field_rid | 0x0400_0000));
        findings
            .infrastructure_fields
            .push(Token::new(first.key_field_rid | 0x0400_0000));
    }

    // Build the .cctor InitializeArray mapping (backing_field → byte[] field)
    // before the owning type search, so we can include salt/key backing field RIDs.
    let init_map = build_array_init_map(&assembly);

    // Collect ALL FieldRVA backing field RIDs for owning type search.
    // This includes backing fields for: encrypted data, salt, key, and any
    // extra fields BitMono added (padding/dummy). Using ALL init_map backing
    // RIDs ensures we find all owning ExplicitLayout types (including the
    // container type that may hold extra non-decryptor fields).
    let owning_field_rids: Vec<u32> = init_map.values().copied().collect();

    // Tag owning types of all infrastructure fields as constant_data_types.
    // Each encrypted string lives in a `<>c` ExplicitLayout valuetype that holds
    // the FieldRVA data. The salt and key also have backing ExplicitLayout types.
    // The container type (e.g., `<PrivateImplementationDetails>`) is also captured
    // if it owns any extra FieldRVA-backed fields beyond the call site set.
    let owning_types = find_field_owning_types(&assembly, &owning_field_rids);
    for type_token in &owning_types {
        findings.constant_data_types.push(*type_token);
    }

    // Tag FieldRVA backing fields in <Module> for byte[] arrays initialized via
    // RuntimeHelpers.InitializeArray. This covers salt, key, and per-string encrypted
    // data arrays — each has a <Module>-level backing field with FieldRVA data.
    // Note: only tag fields that are known call site args. Extra init_map entries
    // (padding/dummy fields) are handled by removing their owning type above.
    if let Some(first) = call_sites.first() {
        for field_rid in [first.salt_field_rid, first.key_field_rid] {
            if let Some(&backing_rid) = init_map.get(&field_rid) {
                findings
                    .constant_data_fields
                    .push(Token::new(backing_rid | 0x0400_0000));
            }
        }
    }
    for site in &call_sites {
        if let Some(&backing_rid) = init_map.get(&site.encrypted_field_rid) {
            findings
                .constant_data_fields
                .push(Token::new(backing_rid | 0x0400_0000));
        }
    }

    if !call_sites.is_empty() {
        events.info(format!(
            "BitMono: tagged {} infrastructure fields, {} constant data types",
            call_sites.len() + 2,
            owning_types.len(),
        ));
    }

    // Stub decryptor method bodies with ldnull; ret.
    // BitMono's Decrypt method may have intentionally corrupted exception handlers
    // as an anti-decompiler measure. Replace with a minimal valid stub so SSA
    // construction succeeds. These methods will be removed by cleanup.
    let mut cil_assembly = assembly.into_assembly();

    for token in &decryptor_tokens {
        let rid = token.row();
        #[allow(clippy::redundant_closure_for_method_calls)]
        let method_row = cil_assembly
            .view()
            .tables()
            .and_then(|t| t.table::<MethodDefRaw>())
            .and_then(|table| table.get(rid));

        if let Some(row) = method_row {
            if row.rva != 0 {
                // Tiny header: code size 2 (ldnull + ret), format 0x02, size in high bits
                // Header byte: (2 << 2) | 0x02 = 0x0A
                let stub_body = vec![0x0A, 0x14, 0x2A]; // tiny header + ldnull + ret
                let placeholder_rva = cil_assembly.store_method_body(stub_body);

                let updated_row = MethodDefRaw {
                    rid: row.rid,
                    token: row.token,
                    offset: row.offset,
                    rva: placeholder_rva,
                    impl_flags: row.impl_flags,
                    flags: row.flags,
                    name: row.name,
                    signature: row.signature,
                    param_list: row.param_list,
                };

                let _ = cil_assembly.table_row_update(
                    TableId::MethodDef,
                    rid,
                    TableDataOwned::MethodDef(updated_row),
                );
            }
        }
    }

    events.info("BitMono: stubbed decryptor method bodies for SSA construction");

    let config = GeneratorConfig::default();
    cil_assembly.into_cilobject_with(ValidationConfig::analysis(), config)
}

// ============================================================================
// Phase B: SSA pass (runs after CalltocalliReversalPass)
// ============================================================================

/// SSA pass that decrypts BitMono-encrypted strings.
///
/// Scans SSA blocks for `Call` to a known decryptor method, traces the three
/// `LoadStaticField` arguments to identify the per-site encrypted data, salt,
/// and key fields. Each site's salt/key pair is used individually to derive AES
/// key material via PBKDF2, then the specific encrypted field is decrypted.
///
/// Caches are used for efficiency but are populated surgically — only fields
/// that are actually referenced as decryptor arguments get decrypted. Key
/// derivation results are cached per `(salt_token, key_token)` pair so that
/// different salt/key combinations (if a variant uses them) are handled correctly.
pub struct StringDecryptionPass {
    decryptor_tokens: HashSet<Token>,
    /// Assembly FieldRVA mapping, built once on first use.
    field_rva_map: OnceLock<HashMap<u32, FieldRvaEntry>>,
    /// Derived AES key material per (salt_token, key_token) pair.
    key_cache: Mutex<KeyCache>,
    /// Decrypted strings per encrypted field token.
    string_cache: Mutex<HashMap<Token, String>>,
}

impl StringDecryptionPass {
    /// Creates a new pass from the findings' decryptor method tokens.
    #[must_use]
    pub fn from_findings(findings: &DeobfuscationFindings) -> Self {
        let decryptor_tokens = findings.decryptor_methods.iter().map(|(_, t)| *t).collect();
        Self {
            decryptor_tokens,
            field_rva_map: OnceLock::new(),
            key_cache: Mutex::new(HashMap::new()),
            string_cache: Mutex::new(HashMap::new()),
        }
    }

    /// Gets or derives AES key material for a specific (salt, key) field pair.
    fn get_or_derive_key(
        &self,
        assembly: &CilObject,
        salt_token: Token,
        key_token: Token,
        field_rva_map: &HashMap<u32, FieldRvaEntry>,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let cache_key = (salt_token, key_token);

        {
            let cache = self.key_cache.lock().unwrap();
            if let Some(cached) = cache.get(&cache_key) {
                return Ok(cached.clone());
            }
        }

        let salt_bytes = get_field_rva_data(assembly, salt_token.row(), field_rva_map)?;
        let key_bytes = get_field_rva_data(assembly, key_token.row(), field_rva_map)?;
        let derived = derive_aes_key_iv(&key_bytes, &salt_bytes);

        self.key_cache
            .lock()
            .unwrap()
            .insert(cache_key, derived.clone());

        Ok(derived)
    }

    /// Gets a cached decrypted string or decrypts it on demand.
    fn decrypt_field(
        &self,
        assembly: &CilObject,
        site: &DecryptionSite,
        field_rva_map: &HashMap<u32, FieldRvaEntry>,
    ) -> Result<String> {
        // Check cache
        {
            let cache = self.string_cache.lock().unwrap();
            if let Some(cached) = cache.get(&site.encrypted_field_token) {
                return Ok(cached.clone());
            }
        }

        // Derive key from this site's specific salt/key pair
        let (aes_key, aes_iv) = self.get_or_derive_key(
            assembly,
            site.salt_field_token,
            site.key_field_token,
            field_rva_map,
        )?;

        // Decrypt this specific encrypted field
        let encrypted =
            get_field_rva_data(assembly, site.encrypted_field_token.row(), field_rva_map)?;
        let decrypted = decrypt_string(&encrypted, &aes_key, &aes_iv)?;

        self.string_cache
            .lock()
            .unwrap()
            .insert(site.encrypted_field_token, decrypted.clone());

        Ok(decrypted)
    }
}

impl SsaPass for StringDecryptionPass {
    fn name(&self) -> &'static str {
        "BitMonoStringDecryption"
    }

    fn description(&self) -> &'static str {
        "Decrypts BitMono AES-encrypted strings via SSA pattern matching"
    }

    fn modification_scope(&self) -> ModificationScope {
        ModificationScope::InstructionsOnly
    }

    fn run_on_method(
        &self,
        ssa: &mut SsaFunction,
        method_token: Token,
        ctx: &CompilerContext,
        assembly: &Arc<CilObject>,
    ) -> Result<bool> {
        let mut changed = false;

        for block_idx in 0..ssa.blocks().len() {
            let sites = find_decryption_sites(ssa, block_idx, &self.decryptor_tokens);
            if sites.is_empty() {
                continue;
            }

            // Build FieldRVA map once (shared across all methods)
            let field_rva_map = self
                .field_rva_map
                .get_or_init(|| build_field_rva_map(assembly));

            // Decrypt each site surgically using its own traced salt/key
            let mut replacements: Vec<StringReplacement> = Vec::new();

            for site in &sites {
                match self.decrypt_field(assembly, site, field_rva_map) {
                    Ok(decrypted) => {
                        replacements.push((
                            site.call_idx,
                            site.call_dest,
                            site.ldsfld_locations,
                            decrypted,
                        ));
                    }
                    Err(_) => continue,
                }
            }

            if replacements.is_empty() {
                continue;
            }

            // Apply replacements in reverse order to preserve indices
            for (call_idx, call_dest, ldsfld_locations, decrypted) in replacements.iter().rev() {
                // Replace the Call instruction in the current block
                if let Some(block) = ssa.block_mut(block_idx) {
                    if let Some(instr) = block.instruction_mut(*call_idx) {
                        instr.set_op(SsaOp::Const {
                            dest: *call_dest,
                            value: ConstValue::DecryptedString(decrypted.clone()),
                        });
                    }
                }

                // NOP the LoadStaticField instructions (may be in different blocks)
                for &(ldsfld_block, ldsfld_idx) in ldsfld_locations {
                    if let Some(block) = ssa.block_mut(ldsfld_block) {
                        if let Some(instr) = block.instruction_mut(ldsfld_idx) {
                            instr.set_op(SsaOp::Nop);
                        }
                    }
                }
                changed = true;
            }

            ctx.events
                .record(EventKind::StringDecrypted)
                .method(method_token)
                .message(format!(
                    "BitMonoStringDecryption: decrypted {} strings in block {}",
                    replacements.len(),
                    block_idx,
                ));
        }

        Ok(changed)
    }
}

/// A decryption site found in SSA form.
struct DecryptionSite {
    /// Index of the Call instruction within its block.
    call_idx: usize,
    /// Destination variable of the Call.
    call_dest: SsaVarId,
    /// Locations of the three LoadStaticField instructions feeding the call.
    /// Each entry is `(block_idx, instr_idx)`. When the LoadStaticField is in the
    /// same block as the Call, `block_idx` equals the call's block. When it is in a
    /// predecessor block (e.g., due to exception handler splitting), `block_idx`
    /// points to that predecessor.
    ldsfld_locations: [(usize, usize); 3],
    /// Token of the encrypted data field (1st arg).
    encrypted_field_token: Token,
    /// Token of the salt field (2nd arg).
    salt_field_token: Token,
    /// Token of the key field (3rd arg).
    key_field_token: Token,
}

/// Finds string decryption call sites in a single SSA block.
///
/// Searches for `Call` instructions targeting a known decryptor method, then
/// traces each argument back to a `LoadStaticField` instruction. The trace
/// first searches backward within the same block; if not found, it searches
/// all preceding blocks. This handles cases where exception handler splitting
/// or other control flow pushes the `LoadStaticField` into a predecessor block.
fn find_decryption_sites(
    ssa: &SsaFunction,
    block_idx: usize,
    decryptor_tokens: &HashSet<Token>,
) -> Vec<DecryptionSite> {
    let mut sites = Vec::new();

    let Some(block) = ssa.block(block_idx) else {
        return sites;
    };

    let instructions = block.instructions();

    for (i, instr) in instructions.iter().enumerate() {
        // Look for Call to a decryptor method
        let (call_dest, call_token, args) = match instr.op() {
            SsaOp::Call { dest, method, args } => {
                let Some(d) = dest else { continue };
                (*d, method.token(), args.clone())
            }
            _ => continue,
        };

        if !decryptor_tokens.contains(&call_token) {
            continue;
        }

        // Need exactly 3 arguments
        if args.len() != 3 {
            continue;
        }

        // Trace each arg back to a LoadStaticField
        let mut ldsfld_locations = [(0usize, 0usize); 3];
        let mut field_tokens = [Token::new(0); 3];
        let mut all_found = true;

        for (arg_idx, arg_var) in args.iter().enumerate() {
            // First: search backward within the same block
            let mut found = false;
            for j in (0..i).rev() {
                let prev = &instructions[j];
                if let SsaOp::LoadStaticField { dest, field } = prev.op() {
                    if *dest == *arg_var {
                        ldsfld_locations[arg_idx] = (block_idx, j);
                        field_tokens[arg_idx] = field.token();
                        found = true;
                        break;
                    }
                }
            }

            // Second: search all preceding blocks (for cross-block definitions)
            if !found {
                for prev_block_idx in (0..block_idx).rev() {
                    let Some(prev_block) = ssa.block(prev_block_idx) else {
                        continue;
                    };
                    for (j, prev_instr) in prev_block.instructions().iter().enumerate().rev() {
                        if let SsaOp::LoadStaticField { dest, field } = prev_instr.op() {
                            if *dest == *arg_var {
                                ldsfld_locations[arg_idx] = (prev_block_idx, j);
                                field_tokens[arg_idx] = field.token();
                                found = true;
                                break;
                            }
                        }
                    }
                    if found {
                        break;
                    }
                }
            }

            if !found {
                all_found = false;
                break;
            }
        }

        if !all_found {
            continue;
        }

        sites.push(DecryptionSite {
            call_idx: i,
            call_dest,
            ldsfld_locations,
            encrypted_field_token: field_tokens[0],
            salt_field_token: field_tokens[1],
            key_field_token: field_tokens[2],
        });
    }

    sites
}

// ============================================================================
// Shared helper functions (used by both phases)
// ============================================================================

/// Collects all byte-level call sites where the decryptor method is called.
///
/// For each call site, walks backward to find the 3 preceding `ldsfld` instructions
/// that provide the encrypted data, salt, and crypt key arguments.
///
/// Handles two patterns:
/// - **Direct call**: `ldsfld; ldsfld; ldsfld; call Decrypt`
/// - **CallToCalli-wrapped**: `ldsfld; ldsfld; ldsfld; <calli sequence with ldc.i4 Decrypt token>`
///   This occurs when both DotNetHook and CallToCalli protect the same call site.
///   Only searched when `search_calli` is true (i.e., DotNetHook was active and
///   stale token correction has been applied).
fn collect_call_sites(
    assembly: &CilObject,
    decryptor_tokens: &[Token],
    search_calli: bool,
) -> Result<Vec<CallSite>> {
    let decryptor_token_values: Vec<u32> = decryptor_tokens.iter().map(|t| t.value()).collect();
    let mut call_sites = Vec::new();

    for method_entry in assembly.methods() {
        let method = method_entry.value();
        let instructions: Vec<_> = method.instructions().collect();

        for (i, instr) in instructions.iter().enumerate() {
            // Pattern 1: direct call to decryptor
            if instr.mnemonic == "call" {
                if let Some(call_target) = instr.get_token_operand() {
                    if decryptor_tokens.contains(&call_target) {
                        let arg_tokens = trace_call_arguments(&instructions, i, 3);
                        if arg_tokens.len() == 3 {
                            call_sites.push(CallSite {
                                encrypted_field_rid: arg_tokens[0].row(),
                                salt_field_rid: arg_tokens[1].row(),
                                key_field_rid: arg_tokens[2].row(),
                            });
                        }
                    }
                }
                continue;
            }

            // Pattern 2: calli wrapping the decryptor (CallToCalli + DotNetHook combo)
            //
            // The CallToCalli pattern embeds the target method token as an ldc.i4 operand
            // within a multi-instruction sequence ending in calli. After DotNetHook reversal,
            // the ldc.i4 contains the corrected decryptor token.
            //
            // Only searched when DotNetHook was active, ensuring stale token correction
            // has been applied (otherwise ldc.i4 values are stale and may collide with
            // unrelated method tokens).
            //
            // Sequence: ldtoken Module / call GetTypeFromHandle / callvirt get_Module /
            //           ldc.i4 <decrypt_token> / call ResolveMethod / ... / calli
            if search_calli && instr.mnemonic == "calli" {
                // Scan backward for ldc.i4 containing a decryptor token value
                let mut calli_start_idx = None;
                for j in (0..i).rev() {
                    if i - j > 15 {
                        break;
                    }
                    if instructions[j].mnemonic.starts_with("ldc.i4") {
                        if let Some(val) = instructions[j].get_i32_operand() {
                            if decryptor_token_values.contains(&(val as u32)) {
                                for k in (0..j).rev() {
                                    if j - k > 5 {
                                        break;
                                    }
                                    if instructions[k].mnemonic == "ldtoken" {
                                        calli_start_idx = Some(k);
                                        break;
                                    }
                                }
                                break;
                            }
                        }
                    }
                }

                if let Some(start_idx) = calli_start_idx {
                    let arg_tokens = trace_call_arguments(&instructions, start_idx, 3);
                    if arg_tokens.len() == 3 {
                        call_sites.push(CallSite {
                            encrypted_field_rid: arg_tokens[0].row(),
                            salt_field_rid: arg_tokens[1].row(),
                            key_field_rid: arg_tokens[2].row(),
                        });
                    }
                }
            }
        }
    }

    Ok(call_sites)
}

/// Traces backward from a `call` instruction to find the N field tokens
/// that produce its arguments.
///
/// Uses the stack behavior of each instruction to walk backward through
/// the instruction stream, identifying which `ldsfld` instructions push
/// the values consumed by the call. This handles intervening junk or
/// dead-code instructions inserted by obfuscators (e.g., BitMethodDotnet's
/// `ldc.i4/ldloc/div/pop/nop` sequences).
///
/// Returns tokens in argument order (first argument first). Returns fewer
/// than `arg_count` tokens if the trace fails to find enough `ldsfld` producers.
fn trace_call_arguments(
    instructions: &[&crate::assembly::Instruction],
    call_idx: usize,
    arg_count: usize,
) -> Vec<Token> {
    // Walk backward from the call, tracking how many stack values we need
    // to "skip over" before reaching the next argument to the call.
    let mut args: Vec<Token> = Vec::with_capacity(arg_count);
    let mut depth: i32 = 0; // extra stack items between us and the next arg

    for j in (0..call_idx).rev() {
        let instr = instructions[j];
        let net = instr.stack_behavior.net_effect as i32;

        // An instruction with net_effect = +1 pushes a value.
        // If depth == 0, this push is a direct argument to the call.
        if net > 0 && depth == 0 {
            if instr.mnemonic == "ldsfld" {
                if let Some(token) = instr.get_token_operand() {
                    args.push(token);
                    if args.len() == arg_count {
                        break;
                    }
                } else {
                    break; // Can't read the token — abort
                }
            } else {
                break; // Non-ldsfld producer — wrong pattern
            }
        } else {
            // Adjust depth: this instruction's pushes feed into something
            // above us, and its pops consume values below.
            depth -= net;
            if depth < 0 {
                break; // Underflow — lost track of the stack
            }
        }
    }

    // Arguments were collected in reverse (last arg first), so reverse
    args.reverse();
    args
}

/// Finds the owning TypeDef tokens for a set of field RIDs.
///
/// Scans the TypeDef table to determine which type owns each field (by its
/// `field_list` range). Returns TypeDef tokens for types that own at least
/// one of the given fields, excluding `<Module>` (RID 1).
fn find_field_owning_types(assembly: &CilObject, field_rids: &[u32]) -> Vec<Token> {
    use std::collections::HashSet;

    let field_set: HashSet<u32> = field_rids.iter().copied().collect();
    let mut result = Vec::new();

    let Some(tables) = assembly.tables() else {
        return result;
    };

    let Some(typedef_table) = tables.table::<TypeDefRaw>() else {
        return result;
    };

    let Some(field_table) = tables.table::<FieldRaw>() else {
        return result;
    };

    let type_count = typedef_table.row_count;
    let field_count = field_table.row_count;

    for type_rid in 2..=type_count {
        let Some(typedef) = typedef_table.get(type_rid) else {
            continue;
        };

        let field_start = typedef.field_list;
        let field_end = if type_rid < type_count {
            typedef_table
                .get(type_rid + 1)
                .map_or(field_count + 1, |t| t.field_list)
        } else {
            field_count + 1
        };

        let owns_target = (field_start..field_end).any(|frid| field_set.contains(&frid));
        if owns_target {
            result.push(Token::from_parts(TableId::TypeDef, type_rid));
        }
    }

    result
}

/// FieldRVA entry data: (rva, data_size).
type FieldRvaEntry = (u32, usize);

/// Builds a map from field RID to (RVA, data_size) for all FieldRVA entries,
/// including indirect entries resolved through `.cctor` `InitializeArray` patterns.
///
/// .NET static byte[] fields are initialized in two steps:
/// 1. A backing field (e.g., `__StaticArrayInitTypeSize=N`) holds the raw data via FieldRVA
/// 2. The `.cctor` copies it to the byte[] field via `RuntimeHelpers.InitializeArray`
///
/// Code references the byte[] field via `ldsfld`, but the actual data is in the
/// backing field's FieldRVA entry. This function maps both direct FieldRVA fields
/// and their corresponding byte[] fields (resolved via the `.cctor` pattern).
fn build_field_rva_map(assembly: &CilObject) -> HashMap<u32, FieldRvaEntry> {
    let mut map = HashMap::new();

    let Some(tables) = assembly.tables() else {
        return map;
    };
    let Some(fieldrva_table) = tables.table::<FieldRvaRaw>() else {
        return map;
    };

    // Build direct FieldRVA map (backing_field_rid -> (rva, size))
    for row in fieldrva_table {
        if row.rva == 0 {
            continue;
        }
        let size = utils::get_field_data_size(assembly, row.field).unwrap_or(0);
        if size > 0 {
            map.insert(row.field, (row.rva, size));
        }
    }

    // Build byte[] field -> backing field mapping from .cctor InitializeArray patterns.
    // Pattern: newarr -> dup -> ldtoken <backing_field> -> call InitializeArray -> stsfld <byte_array_field>
    let init_map = build_array_init_map(assembly);
    for (byte_array_rid, backing_rid) in &init_map {
        if let Some(&entry) = map.get(backing_rid) {
            map.insert(*byte_array_rid, entry);
        }
    }

    map
}

/// Scans the module `.cctor` for `InitializeArray` patterns and builds a mapping
/// from byte[] field RID to backing FieldRVA field RID.
///
/// Looks for the pattern:
/// ```text
/// ldtoken    <backing_field>       // field with FieldRVA data
/// call       RuntimeHelpers.InitializeArray
/// stsfld     <byte_array_field>    // byte[] field referenced in code
/// ```
fn build_array_init_map(assembly: &CilObject) -> HashMap<u32, u32> {
    let mut map = HashMap::new();

    for method_entry in assembly.methods() {
        let method = method_entry.value();

        // Only scan static constructors (.cctor)
        if method.name != ".cctor" {
            continue;
        }

        let instructions: Vec<_> = method.instructions().collect();

        for (i, instr) in instructions.iter().enumerate() {
            // Look for: call to InitializeArray
            if instr.mnemonic != "call" {
                continue;
            }
            let Some(call_token) = instr.get_token_operand() else {
                continue;
            };

            // Check if it's InitializeArray
            let is_init_array = assembly
                .refs_members()
                .get(&call_token)
                .is_some_and(|r| r.value().name == "InitializeArray");

            if !is_init_array {
                continue;
            }

            // Walk backward to find ldtoken <backing_field>
            // Pattern: ... ldtoken <backing_field> -> call InitializeArray -> stsfld <byte_array_field>
            if i < 1 || i + 1 >= instructions.len() {
                continue;
            }

            // Find ldtoken before the call (may be at i-1 or earlier)
            let mut backing_field_token = None;
            for j in (0..i).rev() {
                if instructions[j].mnemonic == "ldtoken" {
                    backing_field_token = instructions[j].get_token_operand();
                    break;
                }
                // Don't search too far back
                if i - j > 3 {
                    break;
                }
            }

            // Find stsfld after the call
            let stsfld_instr = &instructions[i + 1];
            if stsfld_instr.mnemonic != "stsfld" {
                continue;
            }

            if let (Some(backing), Some(byte_array)) =
                (backing_field_token, stsfld_instr.get_token_operand())
            {
                map.insert(byte_array.row(), backing.row());
            }
        }
    }

    map
}

/// Extracts raw bytes for a field's FieldRVA data.
fn get_field_rva_data(
    assembly: &CilObject,
    field_rid: u32,
    field_rva_map: &HashMap<u32, FieldRvaEntry>,
) -> Result<Vec<u8>> {
    let (rva, size) = field_rva_map.get(&field_rid).ok_or_else(|| {
        Error::Deobfuscation(format!("No FieldRVA entry for field RID 0x{:X}", field_rid))
    })?;

    let file = assembly.file();
    let offset = file.rva_to_offset(*rva as usize)?;
    let data = file.data_slice(offset, *size)?;
    Ok(data.to_vec())
}

/// Derives AES-256 key and IV using PBKDF2-HMAC-SHA1.
///
/// Matches .NET's `Rfc2898DeriveBytes(cryptKey, salt, 1000)` which defaults to
/// HMAC-SHA1 and produces 48 bytes (32-byte key + 16-byte IV).
fn derive_aes_key_iv(crypt_key: &[u8], salt: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut derived = [0u8; 48];
    pbkdf2::pbkdf2::<hmac::Hmac<sha1::Sha1>>(crypt_key, salt, 1000, &mut derived)
        .expect("PBKDF2 derivation should not fail with valid inputs");
    (derived[..32].to_vec(), derived[32..48].to_vec())
}

/// Decrypts a single encrypted string using AES-256-CBC with PKCS7 padding.
fn decrypt_string(encrypted: &[u8], key: &[u8], iv: &[u8]) -> Result<String> {
    if encrypted.is_empty() {
        return Ok(String::new());
    }

    // AES-256-CBC requires data to be a multiple of 16 bytes
    if !encrypted.len().is_multiple_of(16) {
        return Err(Error::Deobfuscation(format!(
            "Encrypted data length {} is not a multiple of AES block size",
            encrypted.len()
        )));
    }

    let mut buf = encrypted.to_vec();
    let decryptor = Decryptor::<Aes256>::new_from_slices(key, iv)
        .map_err(|e| Error::Deobfuscation(format!("AES key/IV init failed: {e}")))?;
    let decrypted = decryptor
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|e| Error::Deobfuscation(format!("AES decryption failed: {e}")))?;

    String::from_utf8(decrypted.to_vec())
        .map_err(|e| Error::Deobfuscation(format!("UTF-8 decode failed: {e}")))
}

#[cfg(test)]
mod tests {
    use aes::Aes256;
    use cbc::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
    use cbc::Encryptor;

    use crate::deobfuscation::obfuscators::bitmono::strings::{decrypt_string, derive_aes_key_iv};

    #[test]
    fn test_derive_aes_key_iv_zeros() {
        // BitMono always uses 8 zero bytes for salt and crypt key
        let salt = [0u8; 8];
        let key = [0u8; 8];

        let (aes_key, aes_iv) = derive_aes_key_iv(&key, &salt);

        assert_eq!(aes_key.len(), 32, "AES-256 key should be 32 bytes");
        assert_eq!(aes_iv.len(), 16, "AES IV should be 16 bytes");

        // Verify deterministic output with all-zero inputs
        let (aes_key2, aes_iv2) = derive_aes_key_iv(&key, &salt);
        assert_eq!(aes_key, aes_key2, "Key derivation should be deterministic");
        assert_eq!(aes_iv, aes_iv2, "IV derivation should be deterministic");
    }

    #[test]
    fn test_decrypt_string_roundtrip() {
        let salt = [0u8; 8];
        let key = [0u8; 8];
        let (aes_key, aes_iv) = derive_aes_key_iv(&key, &salt);

        // Encrypt a test string
        let original = "Hello, BitMono!";
        let plaintext = original.as_bytes();

        // Allocate buffer with space for padding (max 1 extra block)
        let mut buf = vec![0u8; plaintext.len() + 16];
        buf[..plaintext.len()].copy_from_slice(plaintext);
        let encryptor = Encryptor::<Aes256>::new_from_slices(&aes_key, &aes_iv).unwrap();
        let encrypted = encryptor
            .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
            .unwrap();

        // Decrypt and verify
        let decrypted = decrypt_string(encrypted, &aes_key, &aes_iv).unwrap();
        assert_eq!(decrypted, original);
    }

    #[test]
    fn test_decrypt_empty_string() {
        let salt = [0u8; 8];
        let key = [0u8; 8];
        let (aes_key, aes_iv) = derive_aes_key_iv(&key, &salt);

        let result = decrypt_string(&[], &aes_key, &aes_iv).unwrap();
        assert_eq!(result, "");
    }

    #[test]
    fn test_decrypt_string_invalid_data() {
        let salt = [0u8; 8];
        let key = [0u8; 8];
        let (aes_key, aes_iv) = derive_aes_key_iv(&key, &salt);

        // Non-multiple-of-16 data should fail
        let result = decrypt_string(&[1, 2, 3], &aes_key, &aes_iv);
        assert!(result.is_err());
    }
}
