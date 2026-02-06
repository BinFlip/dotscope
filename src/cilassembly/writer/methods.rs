//! Method body writer for direct output serialization.
//!
//! This module provides functionality to write method bodies directly to output,
//! handling both tiny and fat header formats, IL code, and exception handlers.
//!
//! # Method Body Format
//!
//! .NET methods have two header formats (ECMA-335 §II.25.4):
//!
//! ## Tiny Format (1 byte header)
//! - Code size ≤ 63 bytes
//! - Max stack = 8 (implied)
//! - No local variables
//! - No exception handlers
//!
//! ## Fat Format (12 byte header)
//! - Code size up to 4GB
//! - Configurable max stack
//! - Local variable signature token
//! - Optional exception handler sections
//!
//! # Exception Handler Sections
//!
//! Exception handlers follow the method code with 4-byte alignment:
//! - **Tiny sections**: 12 bytes per handler (for small offsets)
//! - **Fat sections**: 24 bytes per handler (for large offsets)
//!
//! # IL Token Patching
//!
//! When heaps or tables are rebuilt, IL instructions containing tokens must be patched
//! to reference the new offsets. This module provides [`patch_il_tokens`] which handles:
//!
//! - `ldstr` (0x72): UserString heap references
//! - `call`, `callvirt`, `newobj`, etc.: Metadata table tokens
//!
//! The patching uses remapping tables to translate old token values to new ones.

use std::collections::HashMap;

use crate::{
    assembly::{decode_stream, Operand},
    cilassembly::{changes::ChangeRef, writer::output::Output, AssemblyChanges},
    metadata::{
        method::{ExceptionHandler, ExceptionHandlerFlags, MethodBody},
        tables::TableId,
    },
    Parser, Result,
};

/// UserString heap table ID (0x70) - used in ldstr tokens.
const USERSTRING_TABLE_ID: u8 = 0x70;

/// UserString placeholder ID (0xF0 = 0x70 | 0x80) - indicates unresolved UserString.
const USERSTRING_PLACEHOLDER_ID: u8 = 0xF0;

/// Writes a method body to output at the specified offset.
///
/// Serializes the method header (tiny or fat), IL code, and exception handlers
/// directly to the output file using the [`MethodBody::write_to`] method.
///
/// # Arguments
///
/// * `output` - The memory-mapped output file to write to
/// * `offset` - The file offset where the method body should start (must be 4-byte aligned for fat headers)
/// * `body` - The method body to serialize
/// * `il_code` - The IL bytecode for the method
///
/// # Returns
///
/// The total number of bytes written (header + code + exception handlers + padding).
///
/// # Errors
///
/// Returns an error if writing to the output fails.
pub fn write_method_body(
    output: &mut Output,
    offset: u64,
    body: &MethodBody,
    il_code: &[u8],
) -> Result<u64> {
    // Fat headers require 4-byte alignment
    let start_pos = if body.is_fat {
        align_to_4(offset)
    } else {
        offset
    };

    // Use the OutputWriter to stream directly to the memory-mapped file
    let mut writer = output.writer_at(start_pos);
    let bytes_written = body.write_to(&mut writer, il_code)?;

    Ok(bytes_written)
}

/// Aligns a position to a 4-byte boundary.
#[inline]
fn align_to_4(pos: u64) -> u64 {
    (pos + 3) & !3
}

/// Remaps IL tokens in place using decode-and-patch approach.
///
/// This function handles all token transformations in IL bytecode:
/// - **Token remapping**: Updates tokens when metadata table rows are deleted/shifted
/// - **UserString remapping**: Updates ldstr tokens when the UserString heap changes
/// - **Placeholder resolution**: Resolves placeholder tokens in newly created methods
///
/// The function decodes instructions to find token positions, then patches the token
/// values directly in the byte slice. Since tokens are always 4 bytes, this preserves
/// the exact size and structure of the IL code.
///
/// # Arguments
///
/// * `il_bytes` - The raw IL instruction bytes (modified in place)
/// * `token_map` - Maps old metadata tokens to new tokens (for row deletions)
/// * `userstring_map` - Maps old UserString offsets to new offsets
/// * `changes` - Assembly changes for resolving placeholders (can be None if not needed)
///
/// # Errors
///
/// Returns an error if IL decoding fails.
pub fn remap_il_tokens(
    il_bytes: &mut [u8],
    token_map: &HashMap<u32, u32>,
    userstring_map: &HashMap<u32, u32>,
    changes: Option<&AssemblyChanges>,
) -> Result<()> {
    if il_bytes.is_empty() {
        return Ok(());
    }

    // Decode IL bytes into instructions (includes offset information)
    let mut parser = Parser::new(il_bytes);
    let instructions = decode_stream(&mut parser, 0)?;

    // Find and patch token operands in place
    for instr in &instructions {
        if let Operand::Token(token) = &instr.operand {
            let token_value = token.value();
            let table_id = token_value >> 24;
            let row = token_value & 0x00FF_FFFF;

            let new_token_value = if ChangeRef::is_placeholder(row) {
                // Check for placeholder tokens (row >= 0x800000)
                changes
                    .and_then(|c| c.lookup_by_placeholder(row))
                    .and_then(|cr| cr.token())
                    .map(|t| t.value())
            } else if table_id == USERSTRING_TABLE_ID as u32 {
                // Check for UserString tokens (table ID 0x70 for UserString heap)
                let offset = token_value & 0x00FF_FFFF;
                userstring_map.get(&offset).map(|&new_offset| {
                    ((USERSTRING_TABLE_ID as u32) << 24) | (new_offset & 0x00FF_FFFF)
                })
            } else if table_id == USERSTRING_PLACEHOLDER_ID as u32 {
                // Check for UserString placeholder (0xF0 = 0x70 | 0x80 high bit)
                if let Some(changes) = changes {
                    let offset_part = token_value & 0x00FF_FFFF;
                    let heap_placeholder = 0x8000_0000 | offset_part;
                    if let Some(change_ref) = changes.lookup_by_placeholder(heap_placeholder) {
                        change_ref.offset().map(|actual_offset| {
                            ((USERSTRING_TABLE_ID as u32) << 24) | (actual_offset & 0x00FF_FFFF)
                        })
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                // Regular token remapping
                token_map.get(&token_value).copied()
            };

            if let Some(new_value) = new_token_value {
                // Calculate the byte offset of the token operand
                // Token operand is the last 4 bytes of the instruction
                let token_offset = instr.offset as usize + instr.size as usize - 4;
                if token_offset + 4 <= il_bytes.len() {
                    il_bytes[token_offset..token_offset + 4]
                        .copy_from_slice(&new_value.to_le_bytes());
                }
            }
        }
    }

    Ok(())
}

/// Remaps tokens in a complete method body in place.
///
/// This is the main entry point for method body token remapping. It uses the existing
/// [`MethodBody`] parser to decode the method structure, then patches token values
/// directly in the byte slice.
///
/// It handles:
/// - Fat header local_var_sig_token (at offset 8 in fat headers)
/// - IL instruction tokens via [`remap_il_tokens`]
/// - Exception handler catch type tokens (for EXCEPTION handlers)
///
/// # Arguments
///
/// * `method_body` - The complete method body bytes (modified in place)
/// * `token_map` - Maps old metadata tokens to new tokens
/// * `userstring_map` - Maps old UserString offsets to new offsets
/// * `changes` - Assembly changes for resolving placeholders
///
/// # Errors
///
/// Returns an error if the method body cannot be parsed.
pub fn remap_method_body_tokens(
    method_body: &mut [u8],
    token_map: &HashMap<u32, u32>,
    userstring_map: &HashMap<u32, u32>,
    changes: Option<&AssemblyChanges>,
) -> Result<()> {
    if method_body.is_empty() {
        return Ok(());
    }

    let parsed = MethodBody::from(method_body)?;

    // Handle local_var_sig_token remapping (fat headers only, at offset 8)
    if parsed.is_fat && parsed.local_var_sig_token != 0 {
        let mut new_local_var_sig_token = parsed.local_var_sig_token;
        let table_id = new_local_var_sig_token >> 24;
        let row = new_local_var_sig_token & 0x00FF_FFFF;

        // Check for placeholder
        if table_id == TableId::StandAloneSig.token_type() as u32 && ChangeRef::is_placeholder(row)
        {
            if let Some(changes) = changes {
                if let Some(change_ref) = changes.lookup_by_placeholder(row) {
                    if let Some(resolved_token) = change_ref.token() {
                        new_local_var_sig_token = resolved_token.value();
                    }
                }
            }
        }

        // Apply token remapping
        if let Some(&new_token) = token_map.get(&new_local_var_sig_token) {
            new_local_var_sig_token = new_token;
        }

        // Patch local_var_sig_token in place (offset 8 in fat header)
        if new_local_var_sig_token != parsed.local_var_sig_token && method_body.len() >= 12 {
            method_body[8..12].copy_from_slice(&new_local_var_sig_token.to_le_bytes());
        }
    }

    // Remap IL tokens in place
    let il_start = parsed.size_header;
    let il_end = il_start + parsed.size_code;
    if il_end <= method_body.len() {
        let il_slice = &mut method_body[il_start..il_end];
        remap_il_tokens(il_slice, token_map, userstring_map, changes)?;
    }

    // Remap exception handler catch type tokens in place
    if !parsed.exception_handlers.is_empty() {
        // Exception section starts after IL code, aligned to 4 bytes
        let aligned_offset = (il_end + 3) & !3;
        if aligned_offset < method_body.len() {
            remap_exception_handler_tokens(
                &mut method_body[aligned_offset..],
                &parsed.exception_handlers,
                token_map,
            );
        }
    }

    Ok(())
}

/// Remaps catch type tokens in exception handler section data in place.
///
/// For EXCEPTION handlers, the class token (filter_offset field) may need remapping.
/// This function patches the token values directly in the exception section bytes.
fn remap_exception_handler_tokens(
    exception_data: &mut [u8],
    handlers: &[ExceptionHandler],
    token_map: &HashMap<u32, u32>,
) {
    if exception_data.is_empty() || handlers.is_empty() {
        return;
    }

    // Check if fat format is needed (same logic as encoding)
    let needs_fat = handlers.iter().any(|h| {
        h.try_offset > 0xFFFF
            || h.try_length > 0xFF
            || h.handler_offset > 0xFFFF
            || h.handler_length > 0xFF
    });

    // Section header is 4 bytes, then handlers follow
    let header_size = 4;
    let handler_size = if needs_fat { 24 } else { 12 };
    let class_token_offset = if needs_fat { 16 } else { 8 }; // Offset of ClassToken within handler

    for (i, handler) in handlers.iter().enumerate() {
        // Only EXCEPTION handlers have a class token to remap
        if handler.flags != ExceptionHandlerFlags::EXCEPTION || handler.filter_offset == 0 {
            continue;
        }

        let catch_token = handler.filter_offset;

        // Only remap if it's a type token (TypeRef, TypeDef, or TypeSpec)
        if let Some(table_id) = TableId::from_token_type((catch_token >> 24) as u8) {
            if matches!(
                table_id,
                TableId::TypeRef | TableId::TypeDef | TableId::TypeSpec
            ) {
                if let Some(&new_token) = token_map.get(&catch_token) {
                    let token_pos = header_size + (i * handler_size) + class_token_offset;
                    if token_pos + 4 <= exception_data.len() {
                        exception_data[token_pos..token_pos + 4]
                            .copy_from_slice(&new_token.to_le_bytes());
                    }
                }
            }
        }
    }
}

/// Remaps IL tokens in a method bodies region by modifying data in place.
///
/// This function properly handles the method body region format where each method body
/// has its own header (tiny or fat) followed by IL code and potentially exception handlers.
/// It patches token values directly in the byte slice.
///
/// # Arguments
///
/// * `region_data` - The method bodies region data (modified in place)
/// * `method_offsets` - Offsets of each method body within the region
/// * `userstring_map` - Maps old UserString offsets to new offsets (for ldstr)
/// * `token_map` - Maps old metadata tokens to new tokens (for other instructions)
///
/// # Errors
///
/// Returns an error if a method body cannot be parsed or token remapping fails.
pub fn remap_method_bodies_region(
    region_data: &mut [u8],
    method_offsets: &[usize],
    userstring_map: &HashMap<u32, u32>,
    token_map: &HashMap<u32, u32>,
) -> Result<()> {
    if method_offsets.is_empty() || region_data.is_empty() {
        return Ok(());
    }

    // Only remap if there are tokens to remap
    if token_map.is_empty() && userstring_map.is_empty() {
        return Ok(());
    }

    for &offset in method_offsets {
        if offset >= region_data.len() {
            continue;
        }

        // Parse the method body to get its size (but don't keep the borrow)
        let method_body_size = {
            let method_body_slice = &region_data[offset..];
            match MethodBody::from(method_body_slice) {
                Ok(body) => body.size(),
                Err(_) => {
                    // Skip unparseable method bodies - they may be padding or corrupt
                    continue;
                }
            }
        };

        if offset + method_body_size > region_data.len() {
            continue;
        }

        // Remap tokens in place
        let method_body_bytes = &mut region_data[offset..offset + method_body_size];
        remap_method_body_tokens(method_body_bytes, token_map, userstring_map, None)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Read;
    use tempfile::tempdir;

    #[test]
    fn test_write_tiny_method() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().join("test.bin");

        let mut output = Output::create(&path, 1024).unwrap();

        // Simple tiny method: ldarg.0 (0x02), ret (0x2A)
        let il_code = vec![0x02, 0x2A];
        let body = MethodBody {
            size_code: 2,
            size_header: 1,
            local_var_sig_token: 0,
            max_stack: 8,
            is_fat: false,
            is_init_local: false,
            is_exception_data: false,
            exception_handlers: vec![],
        };

        let bytes_written = write_method_body(&mut output, 0, &body, &il_code).unwrap();
        assert_eq!(bytes_written, 3); // 1 header + 2 code

        output.finalize(None).unwrap();

        // Verify content
        let mut file = File::open(&path).unwrap();
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).unwrap();

        // Header: (2 << 2) | 0x02 = 0x0A
        assert_eq!(contents[0], 0x0A);
        // Code
        assert_eq!(contents[1], 0x02);
        assert_eq!(contents[2], 0x2A);
    }

    #[test]
    fn test_write_fat_method() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().join("test.bin");

        let mut output = Output::create(&path, 1024).unwrap();

        // Fat method with some IL code
        let il_code = vec![0x00; 100]; // 100 nop instructions
        let body = MethodBody {
            size_code: 100,
            size_header: 12,
            local_var_sig_token: 0x11000001,
            max_stack: 8,
            is_fat: true,
            is_init_local: true,
            is_exception_data: false,
            exception_handlers: vec![],
        };

        let bytes_written = write_method_body(&mut output, 0, &body, &il_code).unwrap();
        assert_eq!(bytes_written, 112); // 12 header + 100 code

        output.finalize(None).unwrap();

        // Parse back and verify
        let mut file = File::open(&path).unwrap();
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).unwrap();

        let parsed = MethodBody::from(&contents).unwrap();
        assert!(parsed.is_fat);
        assert!(parsed.is_init_local);
        assert_eq!(parsed.size_code, 100);
        assert_eq!(parsed.max_stack, 8);
        assert_eq!(parsed.local_var_sig_token, 0x11000001);
    }

    /// Helper to read a 32-bit little-endian token from bytes.
    fn read_token_at(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ])
    }

    #[test]
    fn test_remap_il_tokens_ldstr() {
        // ldstr with token 0x70000100 (UserString at offset 0x100)
        let mut il_bytes = vec![
            0x00, // nop
            0x72, 0x00, 0x01, 0x00, 0x70, // ldstr 0x70000100
            0x2A, // ret
        ];

        let mut userstring_map = HashMap::new();
        userstring_map.insert(0x100, 0x200); // Map offset 0x100 -> 0x200

        let token_map = HashMap::new();

        remap_il_tokens(&mut il_bytes, &token_map, &userstring_map, None).unwrap();

        // Check that token was updated to 0x70000200
        let new_token = read_token_at(&il_bytes, 2);
        assert_eq!(new_token, 0x70000200);
    }

    #[test]
    fn test_remap_il_tokens_call() {
        // call with token 0x06000001 (MethodDef RID 1)
        let mut il_bytes = vec![
            0x00, // nop
            0x28, 0x01, 0x00, 0x00, 0x06, // call 0x06000001
            0x2A, // ret
        ];

        let userstring_map = HashMap::new();
        let mut token_map = HashMap::new();
        token_map.insert(0x06000001, 0x06000005); // Map method 1 -> method 5

        remap_il_tokens(&mut il_bytes, &token_map, &userstring_map, None).unwrap();

        // Check that token was updated
        let new_token = read_token_at(&il_bytes, 2);
        assert_eq!(new_token, 0x06000005);
    }

    #[test]
    fn test_remap_il_tokens_multiple() {
        // Multiple instructions with tokens
        let mut il_bytes = vec![
            0x72, 0x00, 0x01, 0x00, 0x70, // ldstr 0x70000100
            0x28, 0x01, 0x00, 0x00, 0x06, // call 0x06000001
            0x6F, 0x02, 0x00, 0x00, 0x06, // callvirt 0x06000002
            0x2A, // ret
        ];

        let mut userstring_map = HashMap::new();
        userstring_map.insert(0x100, 0x200);

        let mut token_map = HashMap::new();
        token_map.insert(0x06000001, 0x06000010);
        token_map.insert(0x06000002, 0x06000020);

        remap_il_tokens(&mut il_bytes, &token_map, &userstring_map, None).unwrap();

        // Check all tokens were updated
        assert_eq!(read_token_at(&il_bytes, 1), 0x70000200);
        assert_eq!(read_token_at(&il_bytes, 6), 0x06000010);
        assert_eq!(read_token_at(&il_bytes, 11), 0x06000020);
    }

    #[test]
    fn test_remap_il_tokens_no_match() {
        // Tokens that don't have mappings should be left unchanged
        let mut il_bytes = vec![
            0x72, 0x00, 0x01, 0x00, 0x70, // ldstr 0x70000100
            0x28, 0x01, 0x00, 0x00, 0x06, // call 0x06000001
            0x2A, // ret
        ];

        let userstring_map = HashMap::new(); // Empty - no mappings
        let token_map = HashMap::new(); // Empty - no mappings

        remap_il_tokens(&mut il_bytes, &token_map, &userstring_map, None).unwrap();

        // Tokens should remain unchanged
        assert_eq!(read_token_at(&il_bytes, 1), 0x70000100);
        assert_eq!(read_token_at(&il_bytes, 6), 0x06000001);
    }

    #[test]
    fn test_remap_il_tokens_two_byte_opcode() {
        // sizeof with token 0x02000001 (TypeDef RID 1)
        // sizeof pushes the size of a type, so it doesn't require stack setup
        let mut il_bytes = vec![
            0x00, // nop
            0xFE, 0x1C, 0x01, 0x00, 0x00, 0x02, // sizeof 0x02000001
            0x26, // pop (discard the result)
            0x2A, // ret
        ];

        let userstring_map = HashMap::new();
        let mut token_map = HashMap::new();
        token_map.insert(0x02000001, 0x02000005);

        remap_il_tokens(&mut il_bytes, &token_map, &userstring_map, None).unwrap();

        // Check token at offset 3 (after 0xFE 0x1C)
        let new_token = read_token_at(&il_bytes, 3);
        assert_eq!(new_token, 0x02000005);
    }
}
