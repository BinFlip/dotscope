//! Shared utility constants and helper functions for ConfuserEx sub-modules.
//!
//! This module consolidates constants and helpers that were previously duplicated
//! across multiple ConfuserEx sub-modules (antitamper, antidebug, antidump, candidates).

use crate::{
    metadata::{method::MethodBody, tables::MethodDefRaw, token::Token},
    CilObject,
};

/// Maximum bytes to read when extracting a method body from memory.
/// This is generous - most methods are under 1KB.
pub(super) const MAX_METHOD_BODY_SIZE: usize = 65536;

/// Helper function to get the full type name from a call operand token.
/// Used by SSA passes for pattern matching.
pub(super) fn get_type_name_from_token(assembly: &CilObject, token: Token) -> Option<String> {
    if let Some(cil_type) = assembly.types().get(&token) {
        return Some(cil_type.fullname());
    }

    // Try MemberRef lookup (for method/field references)
    if let Some(member_ref) = assembly.member_ref(&token) {
        // Extract the declaring type from the MemberRef
        if let Some(type_name) = member_ref.declaredby.fullname() {
            return Some(format!("{}::{}", type_name, member_ref.name));
        }
    }

    None
}

/// Finds methods with encrypted bodies in the assembly.
///
/// These are methods where the RVA is set but the body couldn't be parsed,
/// indicating the method body is encrypted.
pub fn find_encrypted_methods(assembly: &CilObject) -> Vec<Token> {
    assembly
        .methods()
        .iter()
        .filter_map(|entry| {
            let method = entry.value();
            if method.rva.is_some_and(|rva| rva > 0) && !method.has_body() {
                Some(method.token)
            } else {
                None
            }
        })
        .collect()
}

/// Gets the RVA for a method from the raw MethodDef table.
pub(super) fn get_method_rva(assembly: &CilObject, token: Token) -> Option<u32> {
    let tables = assembly.tables()?;
    let method_table = tables.table::<MethodDefRaw>()?;
    let row = token.row();
    let method_row = method_table.get(row)?;
    Some(method_row.rva)
}

/// Extracts a decrypted method body from emulator memory at the given RVA.
///
/// This function:
/// 1. Reads bytes from the virtual memory at ImageBase + RVA
/// 2. Parses the method body to validate and determine size
/// 3. Re-encodes to canonical format
/// 4. Returns the bytes ready for storage in .text section
///
/// # Arguments
///
/// * `memory` - Slice of the virtual image (loaded at ImageBase)
/// * `rva` - The RVA where the method body is located
///
/// # Returns
///
/// The method body bytes (header + IL code + exception handlers), or None if
/// the method body couldn't be parsed.
pub(super) fn extract_method_body_at_rva(memory: &[u8], rva: u32) -> Option<Vec<u8>> {
    let rva_usize = rva as usize;
    if rva_usize >= memory.len() {
        return None;
    }

    // Read up to MAX_METHOD_BODY_SIZE bytes or until end of memory
    let available = memory.len() - rva_usize;
    let read_size = available.min(MAX_METHOD_BODY_SIZE);
    let body_slice = &memory[rva_usize..rva_usize + read_size];

    // Parse the method body to validate and get IL code range
    let body = MethodBody::from(body_slice).ok()?;

    // Extract just the IL code (after header)
    let il_start = body.size_header;
    let il_end = il_start + body.size_code;
    if il_end > body_slice.len() {
        return None;
    }
    let il_code = &body_slice[il_start..il_end];

    // Re-encode to canonical format
    let mut output = Vec::new();
    body.write_to(&mut output, il_code).ok()?;

    Some(output)
}
