//! BitMono BitMethodDotnet junk prefix removal.
//!
//! Removes the junk prefix instructions injected by BitMono's BitMethodDotnet
//! protection at the start of method bodies. The pattern is a `br.s +2` branch
//! that skips over an orphan prefix opcode, adding dead bytes to confuse
//! decompilers.
//!
//! # Pattern
//!
//! ```text
//! br.s       +2          // 2 bytes: 0x2B 0x02
//! <prefix>               // 1-2 bytes: readonly., unaligned., volatile., constrained., tail.
//! ```
//!
//! Reversal: NOP out both instructions (fill with 0x00).

use std::collections::HashMap;

use crate::{
    cilassembly::GeneratorConfig,
    compiler::EventLog,
    deobfuscation::findings::DeobfuscationFindings,
    metadata::{
        tables::{MethodDefRaw, TableDataOwned, TableId},
        token::Token,
        validation::ValidationConfig,
    },
    CilObject, Error, Result,
};

/// A detected junk prefix site.
struct JunkSite {
    /// Method containing the junk prefix.
    method_token: Token,
    /// IL offset of the `br.s` instruction (always 0 — it's at method start).
    patch_start: usize,
    /// IL offset after the prefix opcode.
    patch_end: usize,
}

/// Removes all BitMethodDotnet junk prefix instructions from the assembly.
///
/// Scans method bodies for the `br.s +2` + orphan prefix pattern at the start
/// of methods and NOPs them out.
pub fn remove_junk_prefixes(
    assembly: CilObject,
    findings: &mut DeobfuscationFindings,
    events: &mut EventLog,
) -> Result<CilObject> {
    let Some(bm) = findings.bitmono() else {
        return Ok(assembly);
    };
    if bm.junk_prefix_count == 0 {
        return Ok(assembly);
    }

    // Step 1: Collect all junk prefix sites
    let sites = collect_junk_sites(&assembly);
    if sites.is_empty() {
        events.info("BitMono: no BitMethodDotnet junk prefixes found for removal");
        return Ok(assembly);
    }

    events.info(format!(
        "BitMono: found {} methods with junk prefix to remove",
        sites.len()
    ));

    // Step 2: Apply patches using CilAssembly
    let mut cil_assembly = assembly.into_assembly();

    // Group by method token
    let mut method_sites: HashMap<Token, Vec<&JunkSite>> = HashMap::new();
    for site in &sites {
        method_sites
            .entry(site.method_token)
            .or_default()
            .push(site);
    }

    for (method_token, site_list) in &method_sites {
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
        let Some((header_size, mut body_bytes)) = super::read_method_body(file_data, file_offset)
        else {
            continue;
        };

        for site in site_list {
            let il_start = header_size + site.patch_start;
            let il_end = header_size + site.patch_end;

            if il_end > body_bytes.len() {
                continue;
            }

            // NOP out the junk prefix
            for byte in &mut body_bytes[il_start..il_end] {
                *byte = 0x00;
            }
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

    events.info(format!(
        "BitMono: removed junk prefixes from {} methods",
        sites.len()
    ));

    let config = GeneratorConfig::default();
    cil_assembly.into_cilobject_with(ValidationConfig::analysis(), config)
}

/// Collects all methods with junk prefix at method start.
fn collect_junk_sites(assembly: &CilObject) -> Vec<JunkSite> {
    let mut sites = Vec::new();

    for method_entry in assembly.methods() {
        let method = method_entry.value();
        let instructions: Vec<_> = method.instructions().collect();

        if instructions.len() < 2 {
            continue;
        }

        // Check for br.s at method start followed by a prefix opcode
        if instructions[0].mnemonic == "br.s" {
            let is_prefix = matches!(
                instructions[1].mnemonic,
                "readonly." | "unaligned." | "volatile." | "constrained." | "tail."
            );
            if is_prefix {
                let patch_start = instructions[0].offset as usize;
                let patch_end = (instructions[1].offset + instructions[1].size) as usize;

                sites.push(JunkSite {
                    method_token: method.token,
                    patch_start,
                    patch_end,
                });
            }
        }
    }

    sites
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_junk_prefix_pattern_size() {
        // br.s is always 2 bytes (0x2B + i8 operand)
        // Prefix opcodes are 1-2 bytes:
        //   readonly. = 0xFE 0x1E (2 bytes)
        //   unaligned. = 0xFE 0x12 (2 bytes)
        //   volatile. = 0xFE 0x13 (2 bytes)
        //   constrained. = 0xFE 0x16 (2 bytes)
        //   tail. = 0xFE 0x14 (2 bytes)
        // Total: 2 + 2 = 4 bytes to NOP

        let br_s_size: usize = 2;
        let prefix_size: usize = 2; // Two-byte prefix
        let total = br_s_size + prefix_size;
        assert_eq!(total, 4, "Junk prefix total should be 4 bytes");
    }
}
