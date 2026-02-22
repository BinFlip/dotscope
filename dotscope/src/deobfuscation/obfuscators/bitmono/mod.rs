//! BitMono obfuscator support.
//!
//! BitMono is an open-source .NET packer with 16 independent protections across
//! 4 categories:
//!
//! 1. **Reversible IL-level** — StringsEncryption, CallToCalli, DotNetHook,
//!    UnmanagedString, BitMethodDotnet, AntiDebugBreakpoints
//! 2. **Lossy IL-level** — FullRenamer, NoNamespaces, ObjectReturnType
//! 3. **Cleanup targets** — AntiILdasm, AntiDe4dot, BillionNops, AntiDecompiler
//! 4. **PE-level packers** — BitDotNet, BitDecompiler, BitMono packer, BitTimeDateStamp
//!
//! Unlike ConfuserEx (layered/interdependent) or Obfuscar (single technique), BitMono
//! protections are independent plugins. Each can be detected and reversed individually.
//!
//! # Detection
//!
//! Detection covers all 16 protections using multi-signal scoring. Key discriminators
//! from other obfuscators:
//! - BitMono uses `Rfc2898DeriveBytes` + `RijndaelManaged` (AES); ConfuserEx uses
//!   LZMA + custom XOR/arithmetic
//! - BitMono's FullRenamer produces space-containing names; ConfuserEx uses Unicode
//! - BitMono's `calli` has distinctive `ldtoken <Module>` + `ResolveMethod` sequence
//! - Obfuscar's helper type has `<PrivateImplementationDetails>{GUID}` — not used by BitMono
//!
//! # Test Samples
//!
//! Test samples in `tests/samples/packers/bitmono/0.39.0/` cover each protection:
//!
//! | Sample | Protections |
//! |--------|------------|
//! | `original.exe` | Unprotected baseline |
//! | `bitmono_bitdotnet.exe` | PE signature corruption |
//! | `bitmono_bitdecompiler.exe` | CLR header zeroing |
//! | `bitmono_packer.exe` | Data directory inflation |
//! | `bitmono_pe_combined.exe` | BitDotNet + BitDecompiler |
//! | `bitmono_maximum.exe` | All PE + IL protections |
//! | `bitmono_strings.exe` | StringsEncryption |
//! | `bitmono_calltocalli.exe` | CallToCalli |
//! | `bitmono_dotnethook.exe` | DotNetHook |
//! | `bitmono_unmanagedstring.exe` | UnmanagedString |
//! | `bitmono_antidebug.exe` | AntiDebugBreakpoints |
//! | `bitmono_junk.exe` | BitMethodDotnet + BillionNops |
//! | `bitmono_antide4dot.exe` | AntiDe4dot + AntiILdasm |
//! | `bitmono_renamer.exe` | FullRenamer |
//! | `bitmono_combined.exe` | Multiple IL protections |
//! | `bitmono_maximum_il.exe` | All IL protections |

mod antidebug;
mod antidecompiler;
mod calltocalli;
mod cleanup;
mod detection;
mod dotnethook;
mod findings;
mod junkprefix;
mod strings;
mod unmanagedstring;

pub use detection::detect_bitmono;
pub use findings::BitMonoFindings;

use crate::{
    cilassembly::CleanupRequest,
    compiler::{EventLog, SsaPass},
    deobfuscation::{
        context::AnalysisContext,
        detection::DetectionScore,
        findings::DeobfuscationFindings,
        obfuscators::{Obfuscator, PassPhase},
    },
    CilObject, Result,
};

/// Reads a complete method body (header + IL + exception sections) from PE data.
///
/// Returns `(header_size, body_bytes)` or `None` if the method body cannot be parsed.
pub(super) fn read_method_body(file_data: &[u8], file_offset: usize) -> Option<(usize, Vec<u8>)> {
    if file_offset >= file_data.len() {
        return None;
    }

    let header_byte = file_data[file_offset];
    let (header_size, code_size) = if (header_byte & 0x03) == 0x02 {
        // Tiny header: size in high 6 bits
        (1usize, (header_byte >> 2) as usize)
    } else if (header_byte & 0x03) == 0x03 {
        // Fat header
        if file_offset + 12 > file_data.len() {
            return None;
        }
        let flags_size = u16::from_le_bytes([file_data[file_offset], file_data[file_offset + 1]]);
        let header_words = ((flags_size >> 12) & 0x0F) as usize;
        let cs = u32::from_le_bytes([
            file_data[file_offset + 4],
            file_data[file_offset + 5],
            file_data[file_offset + 6],
            file_data[file_offset + 7],
        ]) as usize;
        (header_words * 4, cs)
    } else {
        return None;
    };

    let body_start = file_offset;
    let total_body_size = header_size + code_size;
    if body_start + total_body_size > file_data.len() {
        return None;
    }

    // For fat headers with MoreSects flag, include exception handler sections
    let body_end = if (header_byte & 0x03) == 0x03 && (header_byte & 0x08) != 0 {
        let sections_start = (body_start + header_size + code_size + 3) & !3;
        find_method_body_end(file_data, sections_start, body_start)
    } else {
        body_start + total_body_size
    };

    let body_bytes = file_data[body_start..body_end].to_vec();
    Some((header_size, body_bytes))
}

/// Finds the end of a method body including exception handler sections.
///
/// For fat method bodies with MoreSects flag, parses exception handler sections
/// to determine the true end of the body data.
pub(super) fn find_method_body_end(
    file_data: &[u8],
    sections_start: usize,
    body_start: usize,
) -> usize {
    let mut pos = sections_start;

    loop {
        if pos + 4 > file_data.len() {
            break;
        }

        let kind = file_data[pos];
        let is_fat_section = (kind & 0x40) != 0;
        let has_more = (kind & 0x80) != 0;

        let section_size = if is_fat_section {
            if pos + 4 > file_data.len() {
                break;
            }
            let size_bytes = [file_data[pos + 1], file_data[pos + 2], file_data[pos + 3]];
            u32::from_le_bytes([size_bytes[0], size_bytes[1], size_bytes[2], 0]) as usize
        } else {
            file_data[pos + 1] as usize
        };

        if section_size == 0 {
            pos += 4;
            break;
        }

        pos += section_size;

        if !has_more {
            break;
        }

        // Align to 4-byte boundary for next section
        pos = (pos + 3) & !3;
    }

    if pos > body_start {
        pos
    } else {
        body_start
    }
}

/// BitMono obfuscator implementation.
///
/// Handles detection and cleanup of assemblies protected by BitMono.
///
/// Detection populates a [`DeobfuscationFindings`] struct that is passed through
/// the pipeline by the engine. The obfuscator itself is stateless.
pub struct BitMonoObfuscator;

impl Default for BitMonoObfuscator {
    fn default() -> Self {
        Self::new()
    }
}

impl BitMonoObfuscator {
    /// Creates a new BitMono obfuscator instance.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Obfuscator for BitMonoObfuscator {
    fn id(&self) -> &str {
        "bitmono"
    }

    fn name(&self) -> &str {
        "BitMono"
    }

    fn detect(&self, assembly: &CilObject, findings: &mut DeobfuscationFindings) -> DetectionScore {
        detection::detect_bitmono(assembly, findings)
    }

    fn deobfuscate(
        &self,
        assembly: CilObject,
        events: &mut EventLog,
        findings: &mut DeobfuscationFindings,
    ) -> Result<CilObject> {
        // Snapshot BitMono predicates before mutable borrows
        let Some(bm) = findings.bitmono() else {
            return Ok(assembly);
        };
        let do_dotnethook = bm.needs_dotnethook_reversal();
        let do_unmanaged = bm.needs_unmanaged_string_reversal();
        let do_junk = bm.needs_junk_prefix_removal();
        let do_antidecompiler = bm.needs_anti_decompiler_fix();
        let do_malformed_eh = bm.needs_malformed_eh_cleanup();
        let do_strings = findings.needs_string_decryption();
        let mut current = assembly;

        // Byte-level phases — these modify raw method bodies and metadata
        // before SSA construction. CallToCalli and AntiDebug are handled
        // by SSA passes returned from `passes()` instead.

        // Phase 4: DotNetHook reversal (byte-level: patches VirtualProtect hooks)
        if do_dotnethook {
            current = dotnethook::reverse_dotnethook(current, findings, events)?;
        }

        // Phase 5: StringsEncryption preparation (byte-level: tags infra fields, stubs decryptor)
        // Actual decryption happens in the StringDecryptionPass SSA pass (after CallToCalli).
        if do_strings {
            current = strings::prepare_string_decryption(current, findings, events)?;
        }

        // Phase 6: UnmanagedString preparation (byte-level: extracts strings, cleans native stubs)
        // Call site replacement (call+newobj → ldstr) is handled by the SSA pass.
        if do_unmanaged {
            current =
                unmanagedstring::prepare_unmanaged_string_reversal(current, findings, events)?;
        }

        // Phase 7: BitMethodDotnet junk prefix removal (byte-level)
        if do_junk {
            current = junkprefix::remove_junk_prefixes(current, findings, events)?;
        }

        // Phase 8: AntiDecompiler attribute fix (byte-level: metadata repair)
        if do_antidecompiler {
            current = antidecompiler::fix_antidecompiler(current, findings, events)?;
        }

        // Phase 9: Malformed exception handler cleanup (byte-level)
        if do_malformed_eh {
            current = antidecompiler::fix_malformed_exception_handlers(current, findings, events)?;
        }

        Ok(current)
    }

    fn passes(&self, findings: &DeobfuscationFindings) -> Vec<(PassPhase, Box<dyn SsaPass>)> {
        let mut passes: Vec<(PassPhase, Box<dyn SsaPass>)> = Vec::new();
        let Some(bm) = findings.bitmono() else {
            return passes;
        };

        // AntiDebugBreakpoints removal — taint-based removal of timing checks.
        // MUST run before CallToCalli: the anti-debug timing check (ble.un.s branch)
        // is injected between GetFunctionPointer and calli, splitting the CallToCalli
        // sequence across basic blocks. Removing the branch first (CfgModifying → full
        // SSA rebuild) merges the blocks so CalltocalliReversalPass can see the full
        // pattern in a single block.
        if findings.needs_anti_debug_patch() {
            let anti_debug_tokens: Vec<_> = findings
                .anti_debug_methods
                .iter()
                .map(|(_, t)| *t)
                .collect();
            passes.push((
                PassPhase::Simplify,
                Box::new(antidebug::AntiDebugRemovalPass::with_methods(
                    anti_debug_tokens,
                )),
            ));
        }

        // CallToCalli reversal — replaces CallIndirect with direct Call.
        // MUST run before string decryption so `call <decrypt>` is visible.
        if bm.needs_calltocalli_reversal() {
            passes.push((
                PassPhase::Simplify,
                Box::new(calltocalli::CalltocalliReversalPass),
            ));
        }

        // String decryption — finds call <decrypt> (now restored by CallToCalli).
        // Runs in Simplify (not Value) because it depends on CallToCalli reversal
        // having already restored `call <decrypt>` from `calli` instructions.
        if findings.needs_string_decryption() {
            passes.push((
                PassPhase::Simplify,
                Box::new(strings::StringDecryptionPass::from_findings(findings)),
            ));
        }

        // UnmanagedString reversal — replaces call+newobj with ldstr.
        // Runs in Simplify for the same reason: call targets must be visible.
        if bm.needs_unmanaged_string_reversal() && bm.unmanaged_string_map.count() > 0 {
            passes.push((
                PassPhase::Simplify,
                Box::new(unmanagedstring::UnmanagedStringReversalPass::from_findings(
                    findings,
                )),
            ));
        }

        passes
    }

    fn cleanup_request(
        &self,
        assembly: &CilObject,
        ctx: &AnalysisContext,
        findings: &DeobfuscationFindings,
    ) -> Result<Option<CleanupRequest>> {
        Ok(cleanup::build_request(assembly, ctx, findings))
    }

    fn description(&self) -> &'static str {
        "BitMono open-source .NET packer — supports PE-level protections, \
         string encryption, CallToCalli, DotNetHook, and IL-level obfuscation"
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        deobfuscation::{
            findings::DeobfuscationFindings,
            obfuscators::{bitmono::BitMonoObfuscator, Obfuscator},
        },
        CilObject, Result, ValidationConfig,
    };

    #[test]
    fn test_bitmono_trait_methods() {
        let obfuscator = BitMonoObfuscator::new();
        assert_eq!(obfuscator.id(), "bitmono");
        assert_eq!(obfuscator.name(), "BitMono");
        assert!(!obfuscator.description().is_empty());
    }

    #[test]
    fn test_detect_original_not_bitmono() -> Result<()> {
        let path = "tests/samples/packers/confuserex/1.6.0/original.exe";

        if !std::path::Path::new(path).exists() {
            eprintln!("Skipping test: sample not found at {path}");
            return Ok(());
        }

        let obfuscator = BitMonoObfuscator::new();
        let assembly = CilObject::from_path_with_validation(path, ValidationConfig::analysis())?;
        let mut findings = DeobfuscationFindings::new();
        let score = obfuscator.detect(&assembly, &mut findings);

        assert!(
            score.score() < 20,
            "Unobfuscated sample should not be detected as BitMono (score: {})",
            score.score()
        );

        Ok(())
    }
}
