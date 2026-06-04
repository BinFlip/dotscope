//! `System.IO.Compression.DeflateStream` and `System.IO.Compression.GZipStream` method hooks.
//!
//! This module provides hook implementations for compressed stream types used by
//! obfuscators for decompressing embedded payloads. On the first read, the entire
//! underlying stream is decompressed and cached for subsequent reads.
//!
//! # Emulated .NET Methods
//!
//! | Method | Description | Implementation |
//! |--------|-------------|----------------|
//! | `DeflateStream..ctor(Stream, CompressionMode)` | Create deflate stream | Wraps underlying stream for decompression |
//! | `DeflateStream.Read(byte[], int, int)` | Read decompressed data | Decompresses on first read, serves from cache |
//! | `DeflateStream.Close()` | Close stream | No-op |
//! | `DeflateStream.Dispose()` | Dispose stream | No-op |
//! | `GZipStream..ctor(Stream, CompressionMode)` | Create gzip stream | Wraps underlying stream for decompression |
//! | `GZipStream.Read(byte[], int, int)` | Read decompressed data | Decompresses on first read, serves from cache |
//! | `GZipStream.Close()` | Close stream | No-op |
//! | `GZipStream.Dispose()` | Dispose stream | No-op |

use crate::{
    emulation::{
        runtime::{
            bcl::io::stream::{stream_close_pre, stream_dispose_pre},
            hook::{Hook, HookContext, HookManager, PreHookResult},
        },
        thread::EmulationThread,
        EmValue,
    },
    utils::{decompress_deflate, decompress_gzip},
    Result,
};

/// Registers all compression stream hooks with the given hook manager.
pub fn register(manager: &HookManager) -> Result<()> {
    // DeflateStream methods
    manager.register(
        Hook::new("System.IO.Compression.DeflateStream..ctor")
            .match_name("System.IO.Compression", "DeflateStream", ".ctor")
            .pre(deflate_stream_ctor_pre),
    )?;

    manager.register(
        Hook::new("System.IO.Compression.DeflateStream.Read")
            .match_name("System.IO.Compression", "DeflateStream", "Read")
            .pre(compressed_stream_read_pre),
    )?;

    manager.register(
        Hook::new("System.IO.Compression.DeflateStream.Close")
            .match_name("System.IO.Compression", "DeflateStream", "Close")
            .pre(stream_close_pre),
    )?;

    manager.register(
        Hook::new("System.IO.Compression.DeflateStream.Dispose")
            .match_name("System.IO.Compression", "DeflateStream", "Dispose")
            .pre(stream_dispose_pre),
    )?;

    // GZipStream methods
    manager.register(
        Hook::new("System.IO.Compression.GZipStream..ctor")
            .match_name("System.IO.Compression", "GZipStream", ".ctor")
            .pre(gzip_stream_ctor_pre),
    )?;

    manager.register(
        Hook::new("System.IO.Compression.GZipStream.Read")
            .match_name("System.IO.Compression", "GZipStream", "Read")
            .pre(compressed_stream_read_pre),
    )?;

    manager.register(
        Hook::new("System.IO.Compression.GZipStream.Close")
            .match_name("System.IO.Compression", "GZipStream", "Close")
            .pre(stream_close_pre),
    )?;

    manager.register(
        Hook::new("System.IO.Compression.GZipStream.Dispose")
            .match_name("System.IO.Compression", "GZipStream", "Dispose")
            .pre(stream_dispose_pre),
    )?;

    Ok(())
}

/// Hook for `System.IO.Compression.DeflateStream..ctor` constructor.
///
/// Creates a DeflateStream wrapping an underlying stream for decompression.
///
/// # Handled Overloads
///
/// - `DeflateStream..ctor(Stream, CompressionMode)`
///
/// # Parameters
///
/// - `stream`: The underlying stream containing compressed data
/// - `mode`: CompressionMode (0=Decompress, 1=Compress)
fn deflate_stream_ctor_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    compressed_stream_ctor(ctx, thread, 0) // 0 = Deflate
}

/// Hook for `System.IO.Compression.GZipStream..ctor` constructor.
///
/// Creates a GZipStream wrapping an underlying stream for decompression.
///
/// # Handled Overloads
///
/// - `GZipStream..ctor(Stream, CompressionMode)`
///
/// # Parameters
///
/// - `stream`: The underlying stream containing compressed data
/// - `mode`: CompressionMode (0=Decompress, 1=Compress)
fn gzip_stream_ctor_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    compressed_stream_ctor(ctx, thread, 1) // 1 = GZip
}

/// Shared constructor logic for DeflateStream and GZipStream.
fn compressed_stream_ctor(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
    compression_type: u8,
) -> PreHookResult {
    let stream_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(None),
    };

    // Get underlying stream argument
    let underlying_stream = match ctx.args.first() {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(None),
    };

    // Get CompressionMode: 0=Decompress, 1=Compress
    #[allow(clippy::cast_sign_loss)]
    let mode = match ctx.args.get(1) {
        Some(EmValue::I32(v)) => *v as u8,
        _ => 0, // Default to Decompress
    };

    try_hook!(thread.heap().replace_with_compressed_stream(
        stream_ref,
        underlying_stream,
        compression_type,
        mode,
    ));

    PreHookResult::Bypass(None)
}

/// Hook for `DeflateStream.Read` and `GZipStream.Read` methods.
///
/// On the first read, decompresses the entire underlying stream's data and caches
/// the result. Subsequent reads serve data from the cache.
///
/// # Handled Overloads
///
/// - `DeflateStream.Read(Byte[], Int32, Int32) -> Int32`
/// - `GZipStream.Read(Byte[], Int32, Int32) -> Int32`
///
/// # Parameters
///
/// - `buffer`: Destination byte array
/// - `offset`: Byte offset in buffer
/// - `count`: Maximum bytes to read
fn compressed_stream_read_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let stream_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
    };

    // Parse buffer, offset, count
    #[allow(clippy::cast_sign_loss)]
    let (buffer_ref, offset, count) = match (ctx.args.first(), ctx.args.get(1), ctx.args.get(2)) {
        (Some(EmValue::ObjectRef(b)), Some(EmValue::I32(o)), Some(EmValue::I32(c))) => {
            (*b, *o as usize, *c as usize)
        }
        _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
    };

    // On first read, decompress the underlying stream data
    if !try_hook!(thread.heap().has_compressed_stream_data(stream_ref)) {
        let Some((underlying, compression_type, _mode)) =
            try_hook!(thread.heap().get_compressed_stream_info(stream_ref))
        else {
            return PreHookResult::Bypass(Some(EmValue::I32(0)));
        };

        let Some((compressed_data, underlying_pos)) =
            try_hook!(thread.heap().get_stream_data(underlying))
        else {
            return PreHookResult::Bypass(Some(EmValue::I32(0)));
        };

        // Use data from the underlying stream's current position, not from offset 0
        let effective_data = compressed_data.get(underlying_pos..).unwrap_or(&[]);

        let decompressed = match compression_type {
            0 => decompress_deflate(effective_data).ok(),
            1 => decompress_gzip(effective_data).ok(),
            _ => None,
        };

        let data = decompressed.unwrap_or_default();
        try_hook!(thread.heap().set_compressed_stream_data(stream_ref, data));
    }

    // Read from the decompressed cache
    let Some(bytes) = try_hook!(thread.heap().read_compressed_stream(stream_ref, count)) else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    // Copy bytes into the output buffer
    for (i, &byte) in bytes.iter().enumerate() {
        try_hook!(thread.heap_mut().set_array_element(
            buffer_ref,
            offset.saturating_add(i),
            EmValue::I32(i32::from(byte)),
        ));
    }

    #[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
    PreHookResult::Bypass(Some(EmValue::I32(bytes.len() as i32)))
}
