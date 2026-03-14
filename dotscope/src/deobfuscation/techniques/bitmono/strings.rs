//! BitMono string encryption detection and decryption technique.
//!
//! Detects BitMono's StringsEncryption protection, which encrypts string literals
//! using AES-256-CBC (via `RijndaelManaged` or `Aes`) with PBKDF2-HMAC-SHA1 key
//! derivation (`Rfc2898DeriveBytes`). Unlike ConfuserEx (which uses emulation),
//! BitMono's encryption is fully static — the key material is embedded as FieldRVA
//! data and the algorithm is standard AES-256-CBC.
//!
//! # CIL Pattern
//!
//! Each string literal is replaced with a 4-instruction sequence:
//! ```text
//! ldsfld     byte[] <encrypted_data_field>     // per-string FieldRVA data
//! ldsfld     byte[] <salt_field>               // shared 8-byte salt
//! ldsfld     byte[] <crypt_key_field>          // shared 8-byte key
//! call       string Decrypt(byte[], byte[], byte[])
//! ```
//!
//! # Detection
//!
//! Scans all static methods for references to crypto types:
//! - `RijndaelManaged` or `Aes` (symmetric cipher)
//! - `Rfc2898DeriveBytes` (key derivation)
//!
//! Also checks for the characteristic decryptor signature: a static method
//! returning `string` that takes 3+ `byte[]` parameters.
//!
//! # Feature Gate
//!
//! The actual string decryption requires the `legacy-crypto` feature for
//! PBKDF2-HMAC-SHA1 key derivation. Detection works without the feature,
//! but decryption is only available when `legacy-crypto` is enabled.
//!
//! # Two-Phase Design
//!
//! **Phase A — `initialize()`** (byte-level, runs before SSA):
//! - Tags infrastructure fields in the analysis context (encrypted data, salt, key fields)
//! - Registers decryptor method tokens so cleanup knows what to remove
//!
//! **Phase B — `StringDecryptionPass`** (SSA pass, runs AFTER `CalltocalliReversalPass`):
//! - Finds `Call` to decryptor methods in SSA blocks
//! - Traces each site's `LoadStaticField` args to identify its specific encrypted
//!   data, salt, and key fields
//! - Derives AES key material per (salt, key) pair (cached for efficiency)
//! - Decrypts only fields actually referenced as decryptor arguments
//! - Replaces `Call` with `DecryptedString` constant, NOPs intermediate instructions

use std::{any::Any, sync::Arc};

use crate::{
    cilassembly::CleanupRequest,
    compiler::SsaPass,
    deobfuscation::{
        context::AnalysisContext,
        techniques::{Detection, Evidence, PassPhase, Technique, TechniqueCategory},
    },
    metadata::{
        signatures::TypeSignature,
        tables::{MemberRefRaw, TableId, TypeDefRaw, TypeRefRaw},
        token::Token,
        typesystem::wellknown,
    },
    CilObject,
};

/// Findings from BitMono string encryption detection.
#[derive(Debug)]
pub struct StringFindings {
    /// Token of the type containing the decryptor method, if identified.
    pub decryptor_type: Option<Token>,
    /// Tokens of identified decryptor methods.
    pub decryptor_tokens: Vec<Token>,
    /// Number of call sites that invoke the decryptor method.
    pub call_sites: usize,
    /// Infrastructure field tokens (encrypted data fields, salt, key).
    /// These are `byte[]` static fields loaded by decryptor call sites.
    pub infrastructure_fields: Vec<Token>,
    /// FieldRVA backing field tokens (ExplicitLayout structs initialized via
    /// `RuntimeHelpers.InitializeArray` to hold raw encrypted data).
    pub constant_data_fields: Vec<Token>,
    /// Types owning the FieldRVA backing fields (ExplicitLayout value types).
    pub constant_data_types: Vec<Token>,
}

/// Detects BitMono's AES+PBKDF2 string encryption.
///
/// Identifies the decryptor infrastructure by scanning for methods that
/// reference `RijndaelManaged`/`Aes` and `Rfc2898DeriveBytes`, or by
/// matching the characteristic `string(byte[], byte[], byte[])` signature.
/// Requires the `bitmono.calli` technique to run first so that `calli`
/// trampolines have been resolved to direct calls before decryption.
pub struct BitMonoStrings;

impl Technique for BitMonoStrings {
    fn id(&self) -> &'static str {
        "bitmono.strings"
    }

    fn name(&self) -> &'static str {
        "BitMono String Decryption"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Value
    }

    fn requires(&self) -> &[&'static str] {
        &["bitmono.calli"]
    }

    #[cfg(feature = "legacy-crypto")]
    fn enabled(&self, _config: &crate::deobfuscation::config::EngineConfig) -> bool {
        true
    }

    #[cfg(not(feature = "legacy-crypto"))]
    fn enabled(&self, _config: &crate::deobfuscation::config::EngineConfig) -> bool {
        false
    }

    fn detect(&self, assembly: &CilObject) -> Detection {
        let mut decryptor_type = None;
        let mut decryptor_tokens = Vec::new();

        // Phase 1: Scan all static methods for crypto type references.
        for method_entry in assembly.methods() {
            let method = method_entry.value();

            if !method.is_static()
                || method.name == wellknown::members::CCTOR
                || method.name == wellknown::members::CTOR
            {
                continue;
            }

            let instructions: Vec<_> = method.instructions().collect();
            if instructions.is_empty() {
                continue;
            }

            let mut has_aes = false;
            let mut has_key_derivation = false;

            for instr in &instructions {
                if let Some(token) = instr.get_token_operand() {
                    if let Some(name) = resolve_type_name(assembly, token) {
                        if name.contains("RijndaelManaged") || name.contains("Aes") {
                            has_aes = true;
                        }
                        if name.contains("Rfc2898DeriveBytes") {
                            has_key_derivation = true;
                        }
                    }
                }
            }

            if has_aes && has_key_derivation {
                decryptor_tokens.push(method.token);
                if decryptor_type.is_none() {
                    if let Some(decl_type) = method.declaring_type_rc() {
                        decryptor_type = Some(decl_type.token);
                    }
                }
                break; // Only one decryptor expected
            }
        }

        // Phase 2: Fallback — look for the characteristic decryptor signature:
        // static, returns string, takes 3+ byte[] parameters.
        if decryptor_tokens.is_empty() {
            for method_entry in assembly.methods() {
                let method = method_entry.value();
                if !method.is_static()
                    || method.name == wellknown::members::CCTOR
                    || method.name == wellknown::members::CTOR
                {
                    continue;
                }
                if method_matches_decryptor_signature(method) {
                    decryptor_tokens.push(method.token);
                    if decryptor_type.is_none() {
                        if let Some(decl_type) = method.declaring_type_rc() {
                            decryptor_type = Some(decl_type.token);
                        }
                    }
                    break;
                }
            }
        }

        if decryptor_tokens.is_empty() {
            return Detection::new_empty();
        }

        // Phase 3: Count call sites and collect infrastructure field tokens.
        // Scan for ldsfld immediately before decryptor call to identify encrypted
        // data, salt, and key fields.
        let mut call_site_count = 0usize;
        let mut infrastructure_fields = Vec::new();

        for method_entry in assembly.methods() {
            let method = method_entry.value();
            let instrs: Vec<_> = method.instructions().collect();
            for (i, instr) in instrs.iter().enumerate() {
                if instr.mnemonic == "call" || instr.mnemonic == "callvirt" {
                    if let Some(token) = instr.get_token_operand() {
                        if decryptor_tokens.contains(&token) {
                            call_site_count += 1;
                            // Walk backwards to find ldsfld args (up to 6 instructions)
                            let start = i.saturating_sub(6);
                            for prev in &instrs[start..i] {
                                if prev.mnemonic == "ldsfld" {
                                    if let Some(field_token) = prev.get_token_operand() {
                                        if !infrastructure_fields.contains(&field_token) {
                                            infrastructure_fields.push(field_token);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Phase 4: Collect FieldRVA backing fields and their owning types.
        // Scan .cctor for RuntimeHelpers.InitializeArray patterns to find the
        // ExplicitLayout value types that hold raw encrypted data.
        let (constant_data_fields, constant_data_types) =
            collect_constant_data_tokens(assembly, &infrastructure_fields);

        let mut evidence = vec![Evidence::BytecodePattern(
            "BitMono string decryptor (AES + Rfc2898DeriveBytes)".to_string(),
        )];

        if call_site_count > 0 {
            evidence.push(Evidence::BytecodePattern(format!(
                "{call_site_count} call sites reference the string decryptor"
            )));
        }

        let findings = StringFindings {
            decryptor_type,
            decryptor_tokens,
            call_sites: call_site_count,
            infrastructure_fields,
            constant_data_fields,
            constant_data_types,
        };

        Detection::new_detected(
            evidence,
            Some(Box::new(findings) as Box<dyn Any + Send + Sync>),
        )
    }

    fn ssa_phase(&self) -> Option<PassPhase> {
        Some(PassPhase::Simplify)
    }

    #[cfg(feature = "legacy-crypto")]
    fn create_pass(
        &self,
        _ctx: &AnalysisContext,
        detection: &Detection,
        _assembly: &Arc<CilObject>,
    ) -> Option<Box<dyn SsaPass>> {
        let findings = detection.findings::<StringFindings>()?;
        Some(Box::new(StringDecryptionPass::from_findings(findings)))
    }

    #[cfg(not(feature = "legacy-crypto"))]
    fn create_pass(
        &self,
        _ctx: &AnalysisContext,
        _detection: &Detection,
        _assembly: &Arc<CilObject>,
    ) -> Option<Box<dyn SsaPass>> {
        None
    }

    fn cleanup(&self, detection: &Detection) -> Option<CleanupRequest> {
        let findings = detection.findings::<StringFindings>()?;

        let mut request = CleanupRequest::new();

        // Remove the decryptor type (cascades to its methods and fields)
        if let Some(decryptor_type) = findings.decryptor_type {
            request.add_type(decryptor_type);
        }

        // Remove infrastructure fields (encrypted data byte[] fields, salt, key)
        for token in &findings.infrastructure_fields {
            request.add_field(*token);
        }

        // Remove FieldRVA backing fields (ExplicitLayout data holders)
        for token in &findings.constant_data_fields {
            request.add_field(*token);
        }

        // Remove ExplicitLayout value types that own the backing fields.
        // These extend System.ValueType, so removing them cascades to remove
        // the ValueType TypeRef → System.Private.CoreLib AssemblyRef chain.
        for token in &findings.constant_data_types {
            request.add_type(*token);
        }

        if request.has_deletions() {
            Some(request)
        } else {
            None
        }
    }
}

/// Collects FieldRVA backing field tokens and their owning ExplicitLayout types.
///
/// Scans `.cctor` methods for `RuntimeHelpers.InitializeArray` patterns to build
/// a mapping from byte[] field → backing FieldRVA field. For each infrastructure
/// field that has a backing field, the backing field token is collected. The owning
/// ExplicitLayout value types are also collected — removing these cascades to remove
/// the `ValueType` TypeRef → `System.Private.CoreLib` AssemblyRef chain.
fn collect_constant_data_tokens(
    assembly: &CilObject,
    infrastructure_fields: &[Token],
) -> (Vec<Token>, Vec<Token>) {
    let mut constant_data_fields = Vec::new();
    let mut constant_data_types = Vec::new();

    if infrastructure_fields.is_empty() {
        return (constant_data_fields, constant_data_types);
    }

    // Build mapping: byte_array_field_token → backing_field_token
    let init_map = crate::deobfuscation::utils::build_init_array_map(assembly);
    if init_map.is_empty() {
        return (constant_data_fields, constant_data_types);
    }

    // Collect backing field tokens for infrastructure fields
    for infra_token in infrastructure_fields {
        if let Some(&backing_token) = init_map.get(infra_token) {
            if !constant_data_fields.contains(&backing_token) {
                constant_data_fields.push(backing_token);
            }
        }
    }

    // Find types owning ANY backing field from the init_map.
    // Intentionally broader than just infrastructure fields — catches container
    // types (e.g. `<PrivateImplementationDetails>`) with extra FieldRVA fields
    // that would otherwise keep System.ValueType alive.
    let all_backing_tokens: Vec<Token> = init_map.values().copied().collect();

    for type_entry in assembly.types().iter() {
        let cil_type = type_entry.value();

        // Skip <Module> — it has a special role and must not be removed
        if cil_type.token.row() == 1 && cil_type.token.table() == 0x02 {
            continue;
        }

        let type_owns_backing = cil_type
            .fields
            .iter()
            .any(|(_, field)| all_backing_tokens.contains(&field.token));

        if type_owns_backing {
            constant_data_types.push(cil_type.token);
        }
    }

    (constant_data_fields, constant_data_types)
}

/// Resolves a metadata token to a type name string for crypto detection.
///
/// For MemberRef tokens, follows the class reference to get the declaring type name.
/// For TypeRef tokens, returns the type name directly. For TypeDef tokens, returns
/// the type name from the local assembly.
fn resolve_type_name(assembly: &CilObject, token: Token) -> Option<String> {
    let tables = assembly.tables()?;
    let strings = assembly.strings()?;

    match token.table() {
        // MemberRef (0x0A) — follow class to get declaring type
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

// ============================================================================
// Phase B: SSA pass (runs after CalltocalliReversalPass)
// ============================================================================
//
// Everything below is gated on the `legacy-crypto` feature, which provides
// the AES and PBKDF2 crates needed for actual string decryption.

#[cfg(feature = "legacy-crypto")]
mod pass {
    use std::{
        collections::{HashMap, HashSet},
        sync::{Mutex, OnceLock},
    };

    use aes::Aes256;
    use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
    use cbc::Decryptor;

    use crate::{
        analysis::{ConstValue, SsaFunction, SsaOp, SsaVarId},
        compiler::{CompilerContext, EventKind, ModificationScope, SsaPass},
        deobfuscation::utils,
        metadata::{tables::FieldRvaRaw, token::Token, typesystem::wellknown},
        CilObject, Error, Result,
    };

    use super::StringFindings;

    /// Cached AES key material: `(derived_key, derived_iv)` per `(salt_token, key_token)` pair.
    type KeyCache = HashMap<(Token, Token), (Vec<u8>, Vec<u8>)>;

    /// A pending string replacement: `(call_idx, call_dest, ldsfld_locations, decrypted_string)`.
    type StringReplacement = (usize, SsaVarId, [(usize, usize); 3], String);

    /// FieldRVA entry data: (rva, data_size).
    type FieldRvaEntry = (u32, usize);

    /// SSA pass that decrypts BitMono-encrypted strings.
    ///
    /// Scans SSA blocks for `Call` to a known decryptor method, traces the three
    /// `LoadStaticField` arguments to identify the per-site encrypted data, salt,
    /// and key fields. Each site's salt/key pair is used individually to derive AES
    /// key material via PBKDF2, then the specific encrypted field is decrypted.
    ///
    /// Caches are used for efficiency but are populated surgically -- only fields
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
        /// Creates a new pass from the detection findings' decryptor method tokens.
        #[must_use]
        pub fn from_findings(findings: &StringFindings) -> Self {
            let decryptor_tokens = findings.decryptor_tokens.iter().copied().collect();
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
            assembly: &CilObject,
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
                for (call_idx, call_dest, ldsfld_locations, decrypted) in replacements.iter().rev()
                {
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

    // ========================================================================
    // SSA pattern matching
    // ========================================================================

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

    // ========================================================================
    // FieldRVA data extraction
    // ========================================================================

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
            if method.name != wellknown::members::CCTOR {
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

    // ========================================================================
    // AES decryption helpers
    // ========================================================================

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

        use super::{decrypt_string, derive_aes_key_iv};

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
}

#[cfg(feature = "legacy-crypto")]
pub use pass::StringDecryptionPass;

#[cfg(test)]
mod tests {
    use crate::deobfuscation::techniques::{bitmono::BitMonoStrings, Technique};
    use crate::test::helpers::load_sample;

    #[test]
    fn test_detect_positive() {
        let assembly = load_sample("tests/samples/packers/bitmono/0.39.0/bitmono_strings.exe");

        let technique = BitMonoStrings;
        let detection = technique.detect(&assembly);

        assert!(
            detection.detected,
            "BitMonoStrings should detect string encryption in bitmono_strings.exe"
        );
        assert!(
            !detection.evidence.is_empty(),
            "Detection should include evidence"
        );
    }

    #[test]
    fn test_detect_negative() {
        let assembly = load_sample("tests/samples/packers/confuserex/1.6.0/original.exe");

        let technique = BitMonoStrings;
        let detection = technique.detect(&assembly);

        assert!(
            !detection.detected,
            "BitMonoStrings should not detect string encryption in a non-BitMono assembly"
        );
    }
}
