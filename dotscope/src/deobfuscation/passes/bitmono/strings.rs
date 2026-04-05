//! BitMono AES string decryption SSA pass.
//!
//! Decrypts BitMono-encrypted strings by tracing SSA `Call` instructions to known
//! decryptor methods, extracting the three `LoadStaticField` arguments (encrypted
//! data, salt, key), deriving AES-256-CBC key material via PBKDF2-HMAC-SHA1, and
//! replacing the call with a `DecryptedString` constant.
//!
//! # Feature Gate
//!
//! This entire module is gated on the `legacy-crypto` feature, which provides
//! the AES and PBKDF2 crates needed for actual string decryption.
//!
//! # Pipeline Position
//!
//! This pass runs in the **Simplify** phase, AFTER `ReflectionDevirtualizationPass`
//! (which resolves `calli` trampolines to direct calls so decryptor call sites
//! become visible).
//!
//! # Algorithm
//!
//! 1. For each block, find `Call` instructions targeting a known decryptor method
//! 2. Trace the three `LoadStaticField` arguments to identify per-site encrypted
//!    data, salt, and key fields
//! 3. Derive AES key material per `(salt_token, key_token)` pair via PBKDF2
//! 4. Decrypt the encrypted field's FieldRVA data using AES-256-CBC
//! 5. Replace `Call` with `Const(DecryptedString(...))` and NOP the `LoadStaticField`s
//!
//! # Example
//!
//! ```text
//! // Before:
//! v1 = LoadStaticField(encrypted_data_field)
//! v2 = LoadStaticField(salt_field)
//! v3 = LoadStaticField(crypt_key_field)
//! v4 = call Decrypt(v1, v2, v3)
//!
//! // After:
//! Nop (was LoadStaticField encrypted_data)
//! Nop (was LoadStaticField salt)
//! Nop (was LoadStaticField key)
//! v4 = Const(DecryptedString("Hello, World!"))
//! ```

use std::{
    collections::{HashMap, HashSet},
    sync::{Mutex, OnceLock},
};

use crate::{
    analysis::{ConstValue, SsaFunction, SsaOp, SsaVarId},
    compiler::{CompilerContext, EventKind, ModificationScope, SsaPass},
    deobfuscation::{
        techniques::BitMonoStringFindings,
        utils::{self, build_init_array_map},
    },
    metadata::{tables::FieldRvaRaw, token::Token},
    utils::{apply_crypto_transform, derive_key_iv, CryptoParameters},
    CilObject, Error, Result,
};

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
    /// Tokens of known decryptor methods.
    decryptor_tokens: HashSet<Token>,
    /// Assembly FieldRVA mapping, built once on first use.
    field_rva_map: OnceLock<HashMap<u32, FieldRvaEntry>>,
    /// Derived AES key material per (salt_token, key_token) pair.
    key_cache: Mutex<KeyCache>,
    /// Decrypted strings per encrypted field token.
    string_cache: Mutex<HashMap<Token, String>>,
    /// Crypto parameters extracted from the decryptor method's SSA.
    crypto_params: CryptoParameters,
}

impl StringDecryptionPass {
    /// Creates a new pass from the detection findings and extracted crypto parameters.
    ///
    /// # Arguments
    ///
    /// * `findings` - Detection findings containing decryptor method tokens.
    /// * `crypto_params` - PBKDF2/AES parameters extracted from the decryptor SSA.
    #[must_use]
    pub fn from_findings(
        findings: &BitMonoStringFindings,
        crypto_params: CryptoParameters,
    ) -> Self {
        let decryptor_tokens = findings.decryptor_tokens.iter().copied().collect();
        Self {
            decryptor_tokens,
            field_rva_map: OnceLock::new(),
            key_cache: Mutex::new(HashMap::new()),
            string_cache: Mutex::new(HashMap::new()),
            crypto_params,
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
            let cache = self
                .key_cache
                .lock()
                .map_err(|e| Error::LockError(format!("key_cache lock failed: {e}")))?;
            if let Some(cached) = cache.get(&cache_key) {
                return Ok(cached.clone());
            }
        }

        let salt_bytes = get_field_rva_data(assembly, salt_token.row(), field_rva_map)?;
        let key_bytes = get_field_rva_data(assembly, key_token.row(), field_rva_map)?;
        let derived = derive_key_iv(&key_bytes, &salt_bytes, &self.crypto_params);

        self.key_cache
            .lock()
            .map_err(|e| Error::LockError(format!("key_cache lock failed: {e}")))?
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
            let cache = self
                .string_cache
                .lock()
                .map_err(|e| Error::LockError(format!("string_cache lock failed: {e}")))?;
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
            .map_err(|e| Error::LockError(format!("string_cache lock failed: {e}")))?
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

        // Build LoadStaticField index once for the entire method
        let ldsfld_index = build_ldsfld_index(ssa);

        for block_idx in 0..ssa.blocks().len() {
            let sites =
                find_decryption_sites(ssa, block_idx, &self.decryptor_tokens, &ldsfld_index);
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

/// Index mapping SSA variable IDs to their `LoadStaticField` definition locations.
///
/// Built once per method via [`build_ldsfld_index`], this replaces the O(I²)
/// cross-block backward search with O(1) HashMap lookups per argument.
type LdsfldIndex = HashMap<SsaVarId, (usize, usize, Token)>;

/// Builds an index of all `LoadStaticField` instructions in the method.
///
/// Returns a map from destination variable ID to `(block_idx, instr_idx, field_token)`.
fn build_ldsfld_index(ssa: &SsaFunction) -> LdsfldIndex {
    let mut index = HashMap::new();
    for (block_idx, block) in ssa.blocks().iter().enumerate() {
        for (instr_idx, instr) in block.instructions().iter().enumerate() {
            if let SsaOp::LoadStaticField { dest, field } = instr.op() {
                index.insert(*dest, (block_idx, instr_idx, field.token()));
            }
        }
    }
    index
}

/// Finds string decryption call sites in a single SSA block.
///
/// Searches for `Call` instructions targeting a known decryptor method, then
/// resolves each argument to a `LoadStaticField` instruction via the pre-built
/// [`LdsfldIndex`]. This is O(1) per argument lookup regardless of method size.
fn find_decryption_sites(
    ssa: &SsaFunction,
    block_idx: usize,
    decryptor_tokens: &HashSet<Token>,
    ldsfld_index: &LdsfldIndex,
) -> Vec<DecryptionSite> {
    let mut sites = Vec::new();

    let Some(block) = ssa.block(block_idx) else {
        return sites;
    };

    for (i, instr) in block.instructions().iter().enumerate() {
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

        // Resolve each arg via the pre-built index
        let mut ldsfld_locations = [(0usize, 0usize); 3];
        let mut field_tokens = [Token::new(0); 3];
        let mut all_found = true;

        for (arg_idx, arg_var) in args.iter().enumerate() {
            if let Some(&(blk, idx, token)) = ldsfld_index.get(arg_var) {
                ldsfld_locations[arg_idx] = (blk, idx);
                field_tokens[arg_idx] = token;
            } else {
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
    let init_map = build_init_array_map(assembly);
    for (byte_array_token, backing_token) in &init_map {
        if let Some(&entry) = map.get(&backing_token.row()) {
            map.insert(byte_array_token.row(), entry);
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

/// Decrypts a single encrypted string using AES-256-CBC with PKCS7 padding.
fn decrypt_string(encrypted: &[u8], key: &[u8], iv: &[u8]) -> Result<String> {
    if encrypted.is_empty() {
        return Ok(String::new());
    }

    let decrypted =
        apply_crypto_transform("AES", key, iv, false, encrypted, 1, 2).ok_or_else(|| {
            Error::Deobfuscation(format!(
                "AES-256-CBC decryption failed for {} bytes",
                encrypted.len()
            ))
        })?;

    let text = String::from_utf8(decrypted)
        .map_err(|e| Error::Deobfuscation(format!("UTF-8 decode failed: {e}")))?;

    // Confidence check: reject strings with a high proportion of control characters
    // (excluding common whitespace), which indicates wrong key material or corruption.
    if !text.is_empty() {
        let control_count = text
            .chars()
            .filter(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
            .count();
        if control_count > text.len() / 2 {
            return Err(Error::Deobfuscation(format!(
                "Decrypted output appears corrupted ({control_count}/{} control chars)",
                text.len()
            )));
        }
    }

    Ok(text)
}

#[cfg(all(test, feature = "legacy-crypto"))]
mod tests {
    use crate::utils::{apply_crypto_transform, derive_key_iv, CryptoParameters};

    use super::decrypt_string;

    #[test]
    fn test_derive_key_iv_zeros() {
        // BitMono always uses 8 zero bytes for salt and crypt key
        let salt = [0u8; 8];
        let key = [0u8; 8];

        let params = CryptoParameters::default();
        let (aes_key, aes_iv) = derive_key_iv(&key, &salt, &params);

        assert_eq!(aes_key.len(), 32, "AES-256 key should be 32 bytes");
        assert_eq!(aes_iv.len(), 16, "AES IV should be 16 bytes");

        // Verify deterministic output with all-zero inputs
        let (aes_key2, aes_iv2) = derive_key_iv(&key, &salt, &params);
        assert_eq!(aes_key, aes_key2, "Key derivation should be deterministic");
        assert_eq!(aes_iv, aes_iv2, "IV derivation should be deterministic");
    }

    #[test]
    fn test_decrypt_string_roundtrip() {
        let salt = [0u8; 8];
        let key = [0u8; 8];
        let params = CryptoParameters::default();
        let (aes_key, aes_iv) = derive_key_iv(&key, &salt, &params);

        // Encrypt a test string using the shared crypto utility
        let original = "Hello, BitMono!";
        let encrypted =
            apply_crypto_transform("AES", &aes_key, &aes_iv, true, original.as_bytes(), 1, 2)
                .expect("AES encryption should succeed");

        // Decrypt and verify
        let decrypted = decrypt_string(&encrypted, &aes_key, &aes_iv).unwrap();
        assert_eq!(decrypted, original);
    }

    #[test]
    fn test_decrypt_empty_string() {
        let salt = [0u8; 8];
        let key = [0u8; 8];
        let params = CryptoParameters::default();
        let (aes_key, aes_iv) = derive_key_iv(&key, &salt, &params);

        let result = decrypt_string(&[], &aes_key, &aes_iv).unwrap();
        assert_eq!(result, "");
    }

    #[test]
    fn test_decrypt_string_invalid_data() {
        let salt = [0u8; 8];
        let key = [0u8; 8];
        let params = CryptoParameters::default();
        let (aes_key, aes_iv) = derive_key_iv(&key, &salt, &params);

        // Non-multiple-of-16 data should fail
        let result = decrypt_string(&[1, 2, 3], &aes_key, &aes_iv);
        assert!(result.is_err());
    }
}
