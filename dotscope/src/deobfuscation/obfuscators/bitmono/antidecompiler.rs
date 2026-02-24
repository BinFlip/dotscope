//! BitMono AntiDecompiler reversal.
//!
//! Resets invalid type attributes injected by BitMono's AntiDecompiler protection.
//! The protection sets `Sealed | ExplicitLayout` on nested `<Module>` types, which
//! causes decompilers like dnSpy to crash or produce garbage output.
//!
//! # Pattern
//!
//! ```text
//! // Before (injected):
//! .class nested private sealed explicit ansi <NestedType>
//!
//! // After (restored):
//! .class nested private auto ansi <NestedType>
//! ```
//!
//! Reversal: clear the `Sealed` flag and reset layout to `AutoLayout` on affected types.

use crate::{
    cilassembly::GeneratorConfig,
    compiler::EventLog,
    deobfuscation::findings::DeobfuscationFindings,
    metadata::{
        method::{MethodBody, MethodImplCodeType},
        tables::{MethodDefRaw, TableDataOwned, TableId, TypeAttributes, TypeDefRaw},
        token::Token,
        validation::ValidationConfig,
    },
    CilObject, Error, Result,
};

/// Removes AntiDecompiler invalid attributes from nested `<Module>` types.
///
/// Resets `Sealed | ExplicitLayout` to `AutoLayout` (clearing both flags) on types
/// identified during detection.
pub fn fix_antidecompiler(
    assembly: CilObject,
    findings: &DeobfuscationFindings,
    events: &mut EventLog,
) -> Result<CilObject> {
    let Some(bm) = findings.bitmono() else {
        return Ok(assembly);
    };
    if bm.anti_decompiler_types.count() == 0 {
        return Ok(assembly);
    }

    let type_tokens: Vec<Token> = bm.anti_decompiler_types.iter().map(|(_, t)| *t).collect();

    events.info(format!(
        "BitMono: fixing AntiDecompiler attributes on {} types",
        type_tokens.len()
    ));

    let mut cil_assembly = assembly.into_assembly();

    for token in &type_tokens {
        let rid = token.row();
        #[allow(clippy::redundant_closure_for_method_calls)]
        let existing_row = cil_assembly
            .view()
            .tables()
            .and_then(|t| t.table::<TypeDefRaw>())
            .and_then(|table| table.get(rid))
            .ok_or_else(|| Error::Deobfuscation(format!("TypeDef row {} not found", rid)))?;

        // Clear Sealed flag and reset layout from ExplicitLayout to AutoLayout
        let mut new_flags = TypeAttributes::new(existing_row.flags);
        new_flags &= !TypeAttributes::SEALED;
        new_flags = (new_flags & !TypeAttributes::LAYOUT_MASK) | TypeAttributes::AUTO_LAYOUT;

        let updated_row = TypeDefRaw {
            rid: existing_row.rid,
            token: existing_row.token,
            offset: existing_row.offset,
            flags: new_flags.bits(),
            type_name: existing_row.type_name,
            type_namespace: existing_row.type_namespace,
            extends: existing_row.extends,
            field_list: existing_row.field_list,
            method_list: existing_row.method_list,
        };

        cil_assembly.table_row_update(
            TableId::TypeDef,
            rid,
            TableDataOwned::TypeDef(updated_row),
        )?;
    }

    events.info(format!(
        "BitMono: restored attributes on {} types",
        type_tokens.len()
    ));

    let config = GeneratorConfig::default();
    cil_assembly.into_cilobject_with(ValidationConfig::analysis(), config)
}

/// Removes malformed exception handlers from affected methods.
///
/// For each method identified with malformed EH during detection:
/// 1. Parse with `from_lenient()` to get the body structure
/// 2. Strip all exception handlers
/// 3. Rebuild the method body via `write_to()`
/// 4. Store the rebuilt body via `store_method_body()`
pub fn fix_malformed_exception_handlers(
    assembly: CilObject,
    findings: &DeobfuscationFindings,
    events: &mut EventLog,
) -> Result<CilObject> {
    let Some(bm) = findings.bitmono() else {
        return Ok(assembly);
    };
    if bm.malformed_eh_methods.count() == 0 {
        return Ok(assembly);
    }

    let method_tokens: Vec<Token> = bm.malformed_eh_methods.iter().map(|(_, t)| *t).collect();

    events.info(format!(
        "BitMono: fixing malformed exception handlers on {} methods",
        method_tokens.len()
    ));

    let mut cil_assembly = assembly.into_assembly();

    // Collect rebuilt bodies and row data before mutating cil_assembly.
    // This avoids borrowing cil_assembly.view() while also calling store_method_body().
    let mut patches: Vec<(u32, MethodDefRaw, Vec<u8>)> = Vec::new();

    for token in &method_tokens {
        let rid = token.row();
        #[allow(clippy::redundant_closure_for_method_calls)]
        let row = cil_assembly
            .view()
            .tables()
            .and_then(|t| t.table::<MethodDefRaw>())
            .and_then(|table| table.get(rid))
            .ok_or_else(|| Error::Deobfuscation(format!("MethodDef row {} not found", rid)))?;

        if row.rva == 0 {
            continue;
        }

        let code_type = MethodImplCodeType::from_impl_flags(row.impl_flags);
        if code_type.contains(MethodImplCodeType::NATIVE)
            || code_type.contains(MethodImplCodeType::RUNTIME)
        {
            continue;
        }

        let file = cil_assembly.view().file();
        let Ok(offset) = file.rva_to_offset(row.rva as usize) else {
            continue;
        };
        let available = file.data().len().saturating_sub(offset);
        if available == 0 {
            continue;
        }

        let body_data = &file.data()[offset..offset + available];
        let Ok(mut body) = MethodBody::from_lenient(body_data) else {
            continue;
        };

        // Strip all exception handlers
        body.exception_handlers.clear();
        body.is_exception_data = false;

        // Extract IL code from original data
        let il_start = offset + body.size_header;
        let il_end = il_start + body.size_code;
        if il_end > file.data().len() {
            continue;
        }
        let il_code = file.data()[il_start..il_end].to_vec();

        // Rebuild the method body
        let mut output = Vec::new();
        body.write_to(&mut output, &il_code)?;

        patches.push((rid, row, output));
    }

    // Apply patches
    for (rid, row, rebuilt_body) in patches {
        let placeholder_rva = cil_assembly.store_method_body(rebuilt_body);

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

        cil_assembly.table_row_update(
            TableId::MethodDef,
            rid,
            TableDataOwned::MethodDef(updated_row),
        )?;
    }

    events.info(format!(
        "BitMono: rebuilt {} methods without malformed exception handlers",
        method_tokens.len()
    ));

    let config = GeneratorConfig::default();
    cil_assembly.into_cilobject_with(ValidationConfig::analysis(), config)
}

#[cfg(test)]
mod tests {
    use crate::metadata::tables::TypeAttributes;

    #[test]
    fn test_flag_clearing() {
        // Simulate AntiDecompiler flags: Sealed (0x100) | ExplicitLayout (0x10) | NestedPrivate (0x03)
        let flags = TypeAttributes::SEALED
            | TypeAttributes::EXPLICIT_LAYOUT
            | TypeAttributes::NESTED_PRIVATE;

        // Clear Sealed and reset layout to AutoLayout
        let mut new_flags = flags;
        new_flags &= !TypeAttributes::SEALED;
        new_flags = (new_flags & !TypeAttributes::LAYOUT_MASK) | TypeAttributes::AUTO_LAYOUT;

        assert!(
            !new_flags.contains(TypeAttributes::SEALED),
            "Sealed should be cleared"
        );
        assert_eq!(
            new_flags.layout(),
            TypeAttributes::AUTO_LAYOUT,
            "Layout should be AutoLayout"
        );
        assert_eq!(
            new_flags.visibility(),
            TypeAttributes::NESTED_PRIVATE,
            "Visibility should be preserved"
        );
    }
}
