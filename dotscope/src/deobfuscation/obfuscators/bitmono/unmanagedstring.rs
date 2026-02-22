//! BitMono UnmanagedString reversal.
//!
//! Reverses BitMono's UnmanagedString protection, which replaces string literals
//! with calls to fake native methods. Each fake native method contains a short
//! x86/x64 code prefix followed by the raw string bytes. The call site invokes
//! the native method and passes the result to a `string` constructor.
//!
//! # Pattern
//!
//! Each string literal is replaced with:
//! ```text
//! call       <fake_native_method>     // Returns pointer to embedded bytes
//! newobj     string::.ctor(sbyte*)    // Or string::.ctor(char*), etc.
//! ```
//!
//! The fake native method body (at its RVA) contains:
//! - **x64**: `lea rax, [rip+1]; ret` (8 bytes) followed by string bytes
//! - **x86**: `call $+5; pop eax; add eax, <offset>; ret` (~20 bytes) followed
//!   by string bytes
//!
//! # Architecture
//!
//! Reversal is split into two phases:
//! 1. **Byte-level preparation** ([`prepare_unmanaged_string_reversal`]): Finds fake
//!    native methods, extracts embedded strings, builds the token→string mapping,
//!    marks native methods for cleanup, and fixes their impl flags.
//! 2. **SSA pass** ([`UnmanagedStringReversalPass`]): Replaces `call <native>` +
//!    `newobj string::.ctor(ptr)` patterns with `DecryptedString` constants,
//!    which the codegen pipeline emits as `ldstr` instructions.

use std::{collections::HashMap, sync::Arc};

use crate::{
    analysis::{x86_native_body_size, ConstValue, SsaFunction, SsaOp, SsaVarId},
    cilassembly::GeneratorConfig,
    compiler::{CompilerContext, EventKind, EventLog, ModificationScope, SsaPass},
    deobfuscation::findings::DeobfuscationFindings,
    metadata::{
        tables::{MethodDefRaw, TableDataOwned, TableId},
        token::Token,
        validation::ValidationConfig,
    },
    CilObject, Result,
};

/// Prepares UnmanagedString reversal: extracts strings and cleans up fake native methods.
///
/// This byte-level phase:
/// 1. Finds fake native methods in `<Module>`
/// 2. Extracts the embedded string bytes from each native method body
/// 3. Stores the native_token → decrypted_string mapping in `findings`
/// 4. Marks fake native methods as proxy methods for cleanup removal
/// 5. Replaces native method bodies with minimal CIL stubs and clears native flags
///
/// The actual call site replacement (call+newobj → ldstr) is handled by
/// [`UnmanagedStringReversalPass`] as an SSA pass.
pub fn prepare_unmanaged_string_reversal(
    assembly: CilObject,
    findings: &mut DeobfuscationFindings,
    events: &mut EventLog,
) -> Result<CilObject> {
    let Some(bm) = findings.bitmono() else {
        return Ok(assembly);
    };
    if bm.unmanaged_string_count == 0 {
        return Ok(assembly);
    }

    // Step 1: Find all fake native methods in <Module>
    let native_methods = find_fake_native_methods(&assembly);
    if native_methods.is_empty() {
        events.info("BitMono: no fake native methods found for UnmanagedString reversal");
        return Ok(assembly);
    }

    // Step 2: Determine PE bitness for native code parsing
    let is_64bit = assembly.file().is_pe32_plus_format().unwrap_or(false);

    // Step 3: Extract strings from native method bodies and store the mapping
    let mut extracted_count = 0usize;

    for native_token in &native_methods {
        if let Some(decrypted) = extract_native_string(&assembly, *native_token, is_64bit) {
            if let Some(bm) = findings.bitmono_mut() {
                bm.unmanaged_string_map.push((*native_token, decrypted));
            }
            extracted_count += 1;
        }
    }

    if extracted_count == 0 {
        events.warn("BitMono: all UnmanagedString extractions failed");
        return Ok(assembly);
    }

    events.info(format!(
        "BitMono: extracted {} strings from {} fake native methods",
        extracted_count,
        native_methods.len()
    ));

    // Step 4: Clean up fake native methods via CilAssembly
    let mut cil_assembly = assembly.into_assembly();

    // Mark fake native methods for cleanup removal and fix their flags so they
    // pass validation as regular CIL methods until the cleanup system removes them.
    // Without this, native methods without matching ImplMap entries fail
    // OwnedMethodValidator during roundtrip.
    for native_token in &native_methods {
        findings.proxy_methods.push(*native_token);

        let rid = native_token.row();
        #[allow(clippy::redundant_closure_for_method_calls)]
        let Some(existing_row) = cil_assembly
            .view()
            .tables()
            .and_then(|t| t.table::<MethodDefRaw>())
            .and_then(|table| table.get(rid))
        else {
            continue;
        };

        // Store a minimal CIL method body (tiny header + ret) for the fake native
        // method. This replaces the native code so validation sees a valid CIL body.
        // Tiny header: (code_size << 2) | 0x02 = (1 << 2) | 0x02 = 0x06
        // Body: 0x2A (ret)
        let minimal_body = vec![0x06, 0x2A];
        let placeholder_rva = cil_assembly.store_method_body(minimal_body);

        // Clear NATIVE code type from impl_flags (set to IL = 0x0000)
        // and clear PRESERVE_SIG (0x0080) if set
        let cleaned_impl_flags = existing_row.impl_flags & !0x0003 & !0x0080;

        // Clear PINVOKE_IMPL (0x2000) from flags
        let cleaned_flags = existing_row.flags & !0x2000;

        let updated_row = MethodDefRaw {
            rid: existing_row.rid,
            token: existing_row.token,
            offset: existing_row.offset,
            rva: placeholder_rva,
            impl_flags: cleaned_impl_flags,
            flags: cleaned_flags,
            name: existing_row.name,
            signature: existing_row.signature,
            param_list: existing_row.param_list,
        };

        if let Err(e) = cil_assembly.table_row_update(
            TableId::MethodDef,
            rid,
            TableDataOwned::MethodDef(updated_row),
        ) {
            events.warn(format!(
                "BitMono: failed to update fake native method flags: {}",
                e
            ));
        }
    }

    let config = GeneratorConfig::default();
    cil_assembly.into_cilobject_with(ValidationConfig::analysis(), config)
}

/// SSA pass that replaces UnmanagedString call+newobj patterns with string constants.
///
/// For each method, scans for the pattern:
/// ```text
/// v1 = Call { method: <fake_native_token>, args: [] }
/// v2 = NewObj { ctor: <string_ctor_token>, args: [v1] }
/// ```
/// and replaces with:
/// ```text
/// Nop  (was Call)
/// v2 = Const { value: DecryptedString("...") }  (was NewObj)
/// ```
///
/// The codegen pipeline handles `DecryptedString` constants by pre-interning them
/// to the #US heap and emitting proper `ldstr` instructions.
pub struct UnmanagedStringReversalPass {
    /// Maps fake native method tokens to their decrypted string values.
    native_string_map: HashMap<Token, String>,
}

impl UnmanagedStringReversalPass {
    /// Creates a new pass from the findings' unmanaged string map.
    #[must_use]
    pub fn from_findings(findings: &DeobfuscationFindings) -> Self {
        let native_string_map = findings
            .bitmono()
            .map(|bm| {
                bm.unmanaged_string_map
                    .iter()
                    .map(|(_, (token, s))| (*token, s.clone()))
                    .collect()
            })
            .unwrap_or_default();
        Self { native_string_map }
    }
}

impl SsaPass for UnmanagedStringReversalPass {
    fn name(&self) -> &'static str {
        "BitMonoUnmanagedString"
    }

    fn description(&self) -> &'static str {
        "Replaces calls to fake native string methods with ldstr constants"
    }

    fn modification_scope(&self) -> ModificationScope {
        ModificationScope::InstructionsOnly
    }

    fn run_on_method(
        &self,
        ssa: &mut SsaFunction,
        _method_token: Token,
        ctx: &CompilerContext,
        _assembly: &Arc<CilObject>,
    ) -> Result<bool> {
        let mut changed = false;

        for block_idx in 0..ssa.blocks().len() {
            let sites = find_unmanaged_string_sites(ssa, block_idx, &self.native_string_map);
            if sites.is_empty() {
                continue;
            }

            // Apply in reverse order to keep indices valid
            let block = match ssa.block_mut(block_idx) {
                Some(b) => b,
                None => continue,
            };

            for site in sites.iter().rev() {
                // Replace NewObj with DecryptedString constant
                if let Some(instr) = block.instruction_mut(site.newobj_idx) {
                    instr.set_op(SsaOp::Const {
                        dest: site.newobj_dest,
                        value: ConstValue::DecryptedString(site.decrypted.clone()),
                    });
                }

                // NOP the Call instruction
                if let Some(instr) = block.instruction_mut(site.call_idx) {
                    instr.set_op(SsaOp::Nop);
                }

                changed = true;
            }

            if !sites.is_empty() {
                ctx.events
                    .record(EventKind::StringDecrypted)
                    .message(format!(
                        "BitMonoUnmanagedString: reversed {} call+newobj sites in block {}",
                        sites.len(),
                        block_idx,
                    ));
            }
        }

        Ok(changed)
    }
}

/// A detected call+newobj site for UnmanagedString reversal.
struct UnmanagedStringSite {
    /// Index of the `Call` instruction in the block.
    call_idx: usize,
    /// Index of the `NewObj` instruction in the block.
    newobj_idx: usize,
    /// SSA variable defined by the NewObj (destination of the string value).
    newobj_dest: SsaVarId,
    /// The decrypted string value.
    decrypted: String,
}

/// Finds call+newobj patterns in a block that target fake native string methods.
fn find_unmanaged_string_sites(
    ssa: &SsaFunction,
    block_idx: usize,
    native_map: &HashMap<Token, String>,
) -> Vec<UnmanagedStringSite> {
    let mut sites = Vec::new();

    let Some(block) = ssa.block(block_idx) else {
        return sites;
    };

    let instructions = block.instructions();

    for (i, instr) in instructions.iter().enumerate() {
        // Look for Call to a fake native method
        let (call_dest, call_token) = match instr.op() {
            SsaOp::Call { dest, method, .. } => {
                let Some(d) = dest else { continue };
                (*d, method.token())
            }
            _ => continue,
        };

        // Check if this call targets a known fake native method
        let Some(decrypted) = native_map.get(&call_token) else {
            continue;
        };

        // Look for NewObj in subsequent instructions that uses the call result
        for (j, next) in instructions.iter().enumerate().skip(i + 1) {
            match next.op() {
                SsaOp::NewObj { dest, args, .. } => {
                    // The NewObj should have exactly one argument: the call result
                    if args.len() == 1 && args[0] == call_dest {
                        sites.push(UnmanagedStringSite {
                            call_idx: i,
                            newobj_idx: j,
                            newobj_dest: *dest,
                            decrypted: decrypted.clone(),
                        });
                        break;
                    }
                }
                // Stop searching if we hit a branch or another use of call_dest
                _ => {
                    // Check if this instruction uses call_dest — if so, stop
                    if next.op().uses().contains(&call_dest) {
                        break;
                    }
                }
            }
        }
    }

    sites
}

/// Finds fake native methods in `<Module>`.
///
/// These are methods with native code type that are NOT real P/Invoke declarations.
/// Handles two variants:
/// - Older BitMono: native methods without PINVOKE or INTERNAL_CALL flags
/// - Newer BitMono: native methods with PINVOKE flag but GUID-format names
fn find_fake_native_methods(assembly: &CilObject) -> Vec<Token> {
    let mut tokens = Vec::new();

    let types = assembly.types();
    let Some(module_type) = types.module_type() else {
        return tokens;
    };

    for (_, method_ref) in module_type.methods.iter() {
        let Some(method) = method_ref.upgrade() else {
            continue;
        };

        if !method.is_code_native() {
            continue;
        }

        // Original check: native without PINVOKE (older BitMono versions)
        if !method.is_pinvoke() && !method.is_internal_call() {
            tokens.push(method.token);
            continue;
        }

        // BitMono sets PINVOKE_IMPL on fake native methods but names them
        // with GUIDs. Real P/Invoke methods have meaningful API names.
        if is_guid_name(&method.name) {
            tokens.push(method.token);
        }
    }

    tokens
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

/// Extracts the embedded string from a fake native method body.
///
/// Uses traversal-based x86 disassembly ([`x86_native_body_size`]) to determine
/// where the executable code ends and the string data begins. This is robust
/// against variations in native code patterns (trampolines, different calling
/// conventions, future BitMono versions) since it follows actual control flow
/// rather than pattern-matching specific byte sequences.
fn extract_native_string(
    assembly: &CilObject,
    native_token: Token,
    is_64bit: bool,
) -> Option<String> {
    let method = assembly.method(&native_token)?;
    let rva = method.rva.filter(|&r| r > 0)?;

    let file = assembly.file();
    let offset = file.rva_to_offset(rva as usize).ok()?;
    let data = file.data();

    if offset >= data.len() {
        return None;
    }

    let native_bytes = &data[offset..];

    // Use traversal-based disassembly to find where the code ends.
    // This follows control flow edges (including trampolines, call targets,
    // and backward jumps) to find the extent of all reachable instructions.
    let prefix_len = x86_native_body_size(native_bytes, is_64bit);
    if prefix_len == 0 || prefix_len >= native_bytes.len() {
        return None;
    }

    let string_bytes = &native_bytes[prefix_len..];

    // Detect encoding: if the second byte is 0x00 and first byte is printable ASCII,
    // the data is likely UTF-16LE (e.g., "Hello" = 48 00 65 00 6C 00 ...).
    // This check must come before the ASCII attempt, which would find the 0x00 at
    // position 1 and incorrectly return just the first character.
    let looks_like_utf16 = string_bytes.len() >= 4
        && string_bytes[0] != 0
        && string_bytes[1] == 0
        && string_bytes[2] != 0
        && string_bytes[3] == 0;

    if looks_like_utf16 {
        // Try UTF-16LE first (char* constructor)
        if let Some(s) = decode_utf16le(string_bytes) {
            return Some(s);
        }
    }

    // Try UTF-8/ASCII (sbyte* constructor)
    if let Some(null_pos) = string_bytes.iter().position(|&b| b == 0) {
        if null_pos > 0 {
            if let Ok(s) = std::str::from_utf8(&string_bytes[..null_pos]) {
                return Some(s.to_string());
            }
        }
    }

    // Fall back to UTF-16LE if ASCII failed
    if !looks_like_utf16 {
        if let Some(s) = decode_utf16le(string_bytes) {
            return Some(s);
        }
    }

    None
}

/// Decodes a null-terminated UTF-16LE byte slice to a String.
fn decode_utf16le(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 2 {
        return None;
    }
    let mut utf16_chars = Vec::new();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let ch = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
        if ch == 0 {
            break;
        }
        utf16_chars.push(ch);
        i += 2;
    }
    if utf16_chars.is_empty() {
        return None;
    }
    String::from_utf16(&utf16_chars).ok()
}

#[cfg(test)]
mod tests {
    use crate::analysis::x86_native_body_size;

    #[test]
    fn test_x86_body_size_x64_pattern() {
        // x64: lea rax, [rip+1]; ret; "Hello"
        let bytes: Vec<u8> = vec![
            0x48, 0x8D, 0x05, 0x01, 0x00, 0x00, 0x00, // lea rax, [rip+1]
            0xC3, // ret
            b'H', b'e', b'l', b'l', b'o', 0x00,
        ];
        let body_size = x86_native_body_size(&bytes, true);
        assert_eq!(body_size, 8, "x64 stub: LEA + RET = 8 bytes");

        let string_bytes = &bytes[body_size..];
        let null_pos = string_bytes.iter().position(|&b| b == 0).unwrap();
        let extracted = std::str::from_utf8(&string_bytes[..null_pos]).unwrap();
        assert_eq!(extracted, "Hello");
    }

    #[test]
    fn test_x86_body_size_simple_pattern() {
        // Simplified x86: push ebp; mov ebp,esp; lea eax,[ebp+8]; pop ebp; ret
        let bytes: Vec<u8> = vec![
            0x55, // push ebp
            0x89, 0xE5, // mov ebp, esp
            0x8D, 0x45, 0x08, // lea eax, [ebp+8]
            0x5D, // pop ebp
            0xC3, // ret
            b'T', b'e', b's', b't', 0x00,
        ];
        let body_size = x86_native_body_size(&bytes, false);
        assert_eq!(body_size, 8);
    }

    #[test]
    fn test_x86_body_size_trampoline_pattern() {
        // BitMono's actual x86 trampoline:
        // push ebp; mov ebp,esp; call $+5; add eax,1; pop ebp; ret;
        // pop eax; add eax,0x0b; jmp -8; <string data>
        let bytes: Vec<u8> = vec![
            0x55, // push ebp
            0x89, 0xE5, // mov ebp, esp
            0xE8, 0x05, 0x00, 0x00, 0x00, // call $+5
            0x83, 0xC0, 0x01, // add eax, 1
            0x5D, // pop ebp
            0xC3, // ret (offset 12)
            0x58, // pop eax (trampoline start — call target)
            0x83, 0xC0, 0x0B, // add eax, 0x0b
            0xEB, 0xF8, // jmp -8 (back to ret)
            // String data starts at offset 19
            b'H', b'e', b'l', b'l', b'o', 0x00,
        ];
        let body_size = x86_native_body_size(&bytes, false);
        assert_eq!(
            body_size, 19,
            "Traversal should follow call target through the trampoline"
        );

        let string_bytes = &bytes[body_size..];
        let null_pos = string_bytes.iter().position(|&b| b == 0).unwrap();
        let extracted = std::str::from_utf8(&string_bytes[..null_pos]).unwrap();
        assert_eq!(extracted, "Hello");
    }

    #[test]
    fn test_x86_body_size_empty() {
        let bytes = vec![];
        assert_eq!(x86_native_body_size(&bytes, false), 0);
    }
}
