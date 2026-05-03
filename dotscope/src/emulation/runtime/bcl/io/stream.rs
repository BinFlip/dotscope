//! `System.IO.Stream` and `System.IO.MemoryStream` method hooks.
//!
//! This module provides hook implementations for stream base class and MemoryStream,
//! which are fundamental to .NET I/O operations. Obfuscators commonly use `MemoryStream`
//! to wrap byte arrays for further processing with `BinaryReader` or compression streams.
//! Streams are backed by [`HeapObject::Stream`] for full data tracking and position management.
//!
//! # Emulated .NET Methods
//!
//! ## MemoryStream Methods
//!
//! | Method | Description | Implementation |
//! |--------|-------------|----------------|
//! | `MemoryStream..ctor(byte[])` | Create stream from bytes | Stores data in heap Stream object |
//! | `MemoryStream.Read(byte[], int, int)` | Read bytes | Reads from Stream data, advances position |
//! | `MemoryStream.ReadByte()` | Read single byte | Reads byte, advances position |
//! | `MemoryStream.Write(byte[], int, int)` | Write bytes | Appends data to stream |
//! | `MemoryStream.WriteByte(byte)` | Write single byte | Appends byte to stream |
//! | `MemoryStream.ToArray()` | Get stream contents | Returns full Stream data as byte array |
//! | `MemoryStream.GetBuffer()` | Get internal buffer | Returns full Stream data as byte array |
//! | `MemoryStream.get_Length` | Stream length | Returns actual data length |
//! | `MemoryStream.get_Capacity` | Stream capacity | Returns data length (simplified) |
//! | `MemoryStream.get_Position` | Current position | Returns current read position |
//! | `MemoryStream.set_Position` | Set position | Updates stream position |
//! | `MemoryStream.Seek(long, SeekOrigin)` | Seek to position | Updates position based on origin |
//! | `MemoryStream.SetLength(long)` | Set stream length | Truncates or extends stream |
//! | `MemoryStream.CopyTo(Stream)` | Copy to another stream | Copies remaining data |
//! | `MemoryStream.Flush()` | Flush stream | No-op |
//! | `MemoryStream.Close()` | Close stream | No-op |
//! | `MemoryStream.Dispose()` | Dispose stream | No-op |
//! | `MemoryStream.get_CanRead` | Can read | Always true |
//! | `MemoryStream.get_CanSeek` | Can seek | Always true |
//! | `MemoryStream.get_CanWrite` | Can write | Always true |
//!
//! ## Stream Base Class Methods
//!
//! | Method | Description | Implementation |
//! |--------|-------------|----------------|
//! | `Stream.Read(byte[], int, int)` | Read bytes | Reads from Stream data |
//! | `Stream.ReadByte()` | Read single byte | Reads byte from Stream |
//! | `Stream.Write(byte[], int, int)` | Write bytes | Appends data to stream |
//! | `Stream.WriteByte(byte)` | Write single byte | Appends byte to stream |
//! | `Stream.get_Length` | Stream length | Returns actual length |
//! | `Stream.get_Position` | Current position | Returns current position |
//! | `Stream.set_Position` | Set position | Updates stream position |
//! | `Stream.Seek(long, SeekOrigin)` | Seek to position | Updates position based on origin |
//! | `Stream.SetLength(long)` | Set stream length | Truncates or extends stream |
//! | `Stream.CopyTo(Stream)` | Copy to another stream | Copies remaining data |
//! | `Stream.Flush()` | Flush stream | No-op |
//! | `Stream.Close()` | Close stream | No-op |
//! | `Stream.Dispose()` | Dispose stream | No-op |
//! | `Stream.get_CanRead` | Can read | Always true |
//! | `Stream.get_CanSeek` | Can seek | Always true |
//! | `Stream.get_CanWrite` | Can write | Always true |
//!
//! # Implementation Notes
//!
//! Stream data is stored in [`HeapObject::Stream`] which provides:
//!
//! - **Full data tracking**: Stream contents are stored and retrieved correctly
//! - **Position tracking**: Read position advances as data is consumed
//! - **Length tracking**: Actual data length is available
//! - **Write support**: `MemoryStream.Write` and `WriteByte` operations append data to streams
//!
//! [`HeapObject::Stream`]: crate::emulation::memory::HeapObject::Stream

use crate::{
    emulation::{
        runtime::hook::{Hook, HookContext, HookManager, PreHookResult},
        thread::EmulationThread,
        EmValue,
    },
    utils::{apply_crypto_transform, decompress_deflate, decompress_gzip},
    Result,
};

/// Registers all Stream and MemoryStream method hooks with the given hook manager.
///
/// # Arguments
///
/// * `manager` - The [`HookManager`] to register hooks with
pub fn register(manager: &HookManager) -> Result<()> {
    // MemoryStream methods
    manager.register(
        Hook::new("System.IO.MemoryStream..ctor")
            .match_name("System.IO", "MemoryStream", ".ctor")
            .pre(memory_stream_ctor_pre),
    )?;

    manager.register(
        Hook::new("System.IO.MemoryStream.Read")
            .match_name("System.IO", "MemoryStream", "Read")
            .pre(stream_read_pre),
    )?;

    manager.register(
        Hook::new("System.IO.MemoryStream.ReadByte")
            .match_name("System.IO", "MemoryStream", "ReadByte")
            .pre(stream_read_byte_pre),
    )?;

    manager.register(
        Hook::new("System.IO.MemoryStream.Write")
            .match_name("System.IO", "MemoryStream", "Write")
            .pre(stream_write_pre),
    )?;

    manager.register(
        Hook::new("System.IO.MemoryStream.ToArray")
            .match_name("System.IO", "MemoryStream", "ToArray")
            .pre(memory_stream_to_array_pre),
    )?;

    manager.register(
        Hook::new("System.IO.MemoryStream.get_Length")
            .match_name("System.IO", "MemoryStream", "get_Length")
            .pre(stream_get_length_pre),
    )?;

    manager.register(
        Hook::new("System.IO.MemoryStream.get_Position")
            .match_name("System.IO", "MemoryStream", "get_Position")
            .pre(stream_get_position_pre),
    )?;

    manager.register(
        Hook::new("System.IO.MemoryStream.set_Position")
            .match_name("System.IO", "MemoryStream", "set_Position")
            .pre(stream_set_position_pre),
    )?;

    manager.register(
        Hook::new("System.IO.MemoryStream.WriteByte")
            .match_name("System.IO", "MemoryStream", "WriteByte")
            .pre(stream_write_byte_pre),
    )?;

    manager.register(
        Hook::new("System.IO.MemoryStream.Seek")
            .match_name("System.IO", "MemoryStream", "Seek")
            .pre(stream_seek_pre),
    )?;

    manager.register(
        Hook::new("System.IO.MemoryStream.GetBuffer")
            .match_name("System.IO", "MemoryStream", "GetBuffer")
            .pre(memory_stream_get_buffer_pre),
    )?;

    manager.register(
        Hook::new("System.IO.MemoryStream.SetLength")
            .match_name("System.IO", "MemoryStream", "SetLength")
            .pre(stream_set_length_pre),
    )?;

    manager.register(
        Hook::new("System.IO.MemoryStream.get_Capacity")
            .match_name("System.IO", "MemoryStream", "get_Capacity")
            .pre(stream_get_length_pre),
    )?;

    manager.register(
        Hook::new("System.IO.MemoryStream.CopyTo")
            .match_name("System.IO", "MemoryStream", "CopyTo")
            .pre(stream_copy_to_pre),
    )?;

    manager.register(
        Hook::new("System.IO.MemoryStream.Flush")
            .match_name("System.IO", "MemoryStream", "Flush")
            .pre(stream_close_pre),
    )?;

    manager.register(
        Hook::new("System.IO.MemoryStream.Close")
            .match_name("System.IO", "MemoryStream", "Close")
            .pre(stream_close_pre),
    )?;

    manager.register(
        Hook::new("System.IO.MemoryStream.Dispose")
            .match_name("System.IO", "MemoryStream", "Dispose")
            .pre(stream_dispose_pre),
    )?;

    manager.register(
        Hook::new("System.IO.MemoryStream.get_CanRead")
            .match_name("System.IO", "MemoryStream", "get_CanRead")
            .pre(stream_can_true_pre),
    )?;

    manager.register(
        Hook::new("System.IO.MemoryStream.get_CanSeek")
            .match_name("System.IO", "MemoryStream", "get_CanSeek")
            .pre(stream_can_true_pre),
    )?;

    manager.register(
        Hook::new("System.IO.MemoryStream.get_CanWrite")
            .match_name("System.IO", "MemoryStream", "get_CanWrite")
            .pre(stream_can_true_pre),
    )?;

    // Stream base class methods
    manager.register(
        Hook::new("System.IO.Stream.Read")
            .match_name("System.IO", "Stream", "Read")
            .pre(stream_read_pre),
    )?;

    manager.register(
        Hook::new("System.IO.Stream.ReadByte")
            .match_name("System.IO", "Stream", "ReadByte")
            .pre(stream_read_byte_pre),
    )?;

    manager.register(
        Hook::new("System.IO.Stream.get_Length")
            .match_name("System.IO", "Stream", "get_Length")
            .pre(stream_get_length_pre),
    )?;

    manager.register(
        Hook::new("System.IO.Stream.get_Position")
            .match_name("System.IO", "Stream", "get_Position")
            .pre(stream_get_position_pre),
    )?;

    manager.register(
        Hook::new("System.IO.Stream.set_Position")
            .match_name("System.IO", "Stream", "set_Position")
            .pre(stream_set_position_pre),
    )?;

    manager.register(
        Hook::new("System.IO.Stream.Write")
            .match_name("System.IO", "Stream", "Write")
            .pre(stream_write_pre),
    )?;

    manager.register(
        Hook::new("System.IO.Stream.WriteByte")
            .match_name("System.IO", "Stream", "WriteByte")
            .pre(stream_write_byte_pre),
    )?;

    manager.register(
        Hook::new("System.IO.Stream.Seek")
            .match_name("System.IO", "Stream", "Seek")
            .pre(stream_seek_pre),
    )?;

    manager.register(
        Hook::new("System.IO.Stream.SetLength")
            .match_name("System.IO", "Stream", "SetLength")
            .pre(stream_set_length_pre),
    )?;

    manager.register(
        Hook::new("System.IO.Stream.CopyTo")
            .match_name("System.IO", "Stream", "CopyTo")
            .pre(stream_copy_to_pre),
    )?;

    manager.register(
        Hook::new("System.IO.Stream.Flush")
            .match_name("System.IO", "Stream", "Flush")
            .pre(stream_close_pre),
    )?;

    manager.register(
        Hook::new("System.IO.Stream.Close")
            .match_name("System.IO", "Stream", "Close")
            .pre(stream_close_pre),
    )?;

    manager.register(
        Hook::new("System.IO.Stream.Dispose")
            .match_name("System.IO", "Stream", "Dispose")
            .pre(stream_dispose_pre),
    )?;

    manager.register(
        Hook::new("System.IO.Stream.get_CanRead")
            .match_name("System.IO", "Stream", "get_CanRead")
            .pre(stream_can_true_pre),
    )?;

    manager.register(
        Hook::new("System.IO.Stream.get_CanSeek")
            .match_name("System.IO", "Stream", "get_CanSeek")
            .pre(stream_can_true_pre),
    )?;

    manager.register(
        Hook::new("System.IO.Stream.get_CanWrite")
            .match_name("System.IO", "Stream", "get_CanWrite")
            .pre(stream_can_true_pre),
    )?;

    Ok(())
}

/// Hook for `System.IO.MemoryStream..ctor` constructor.
///
/// # Handled Overloads
///
/// - `MemoryStream..ctor()` - Creates an empty stream
/// - `MemoryStream..ctor(Byte[])` - Creates a stream from byte array
///
/// # Parameters
///
/// - `buffer`: Optional byte array containing initial stream data
fn memory_stream_ctor_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    // Get the byte array argument (may be None for empty stream)
    let data = if let Some(EmValue::ObjectRef(array_ref)) = ctx.args.first() {
        // Try get_byte_array first (for byte[] arrays with I32 elements)
        // Fall back to get_array_as_bytes which handles multi-byte element types
        // (e.g., uint[] arrays serialized to bytes in little-endian order)
        let primary = try_hook!(thread.heap().get_byte_array(*array_ref));
        if let Some(bytes) = primary {
            bytes
        } else {
            try_hook!(thread
                .heap()
                .get_array_as_bytes(*array_ref, ctx.pointer_size))
            .unwrap_or_default()
        }
    } else {
        Vec::new()
    };

    match ctx.this {
        Some(EmValue::ObjectRef(stream_ref)) => {
            // Instance call: replace the allocated object with a Stream
            try_hook!(thread.heap_mut().replace_with_stream(*stream_ref, data));
            PreHookResult::Bypass(None) // Constructor returns void
        }
        _ => {
            // Factory pattern: allocate a new Stream directly
            let type_token = thread.resolve_type_token("System.IO", "MemoryStream");
            match thread.heap_mut().alloc_stream(data, type_token) {
                Ok(stream_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(stream_ref))),
                Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
            }
        }
    }
}

/// Hook for `System.IO.Stream.Read` and `System.IO.MemoryStream.Read` methods.
///
/// # Handled Overloads
///
/// - `Stream.Read(Byte[], Int32, Int32) -> Int32`
/// - `MemoryStream.Read(Byte[], Int32, Int32) -> Int32`
///
/// # Parameters
///
/// - `buffer`: Destination byte array to read into
/// - `offset`: Zero-based byte offset in buffer to begin storing data
/// - `count`: Maximum number of bytes to read
///
/// # Returns
///
/// Number of bytes actually read into the buffer
fn stream_read_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    // Get the stream reference
    let stream_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        Some(EmValue::Null) => return PreHookResult::throw_null_reference(),
        _ => return PreHookResult::throw_object_disposed(),
    };

    // Parse arguments: buffer, offset, count
    // Safe: values validated as non-negative
    #[allow(clippy::cast_sign_loss)]
    let (buffer_ref, offset, count) = match (ctx.args.first(), ctx.args.get(1), ctx.args.get(2)) {
        (Some(EmValue::ObjectRef(b)), Some(EmValue::I32(o)), Some(EmValue::I32(c))) => {
            (*b, *o as usize, *c as usize)
        }
        _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
    };

    // Read up to `count` bytes from the stream (advances position internally)
    let Some(bytes) = try_hook!(thread.heap().stream_read(stream_ref, count)) else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    let to_read = bytes.len();

    // Copy read bytes into the destination buffer array
    for (i, &byte) in bytes.iter().enumerate() {
        try_hook!(thread.heap_mut().set_array_element(
            buffer_ref,
            offset + i,
            EmValue::I32(i32::from(byte)),
        ));
    }

    #[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
    PreHookResult::Bypass(Some(EmValue::I32(to_read as i32)))
}

/// Hook for `System.IO.Stream.ReadByte` and `System.IO.MemoryStream.ReadByte` methods.
///
/// # Handled Overloads
///
/// - `Stream.ReadByte() -> Int32`
/// - `MemoryStream.ReadByte() -> Int32`
///
/// # Returns
///
/// The byte cast to `Int32`, or -1 if at end of stream
fn stream_read_byte_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    // Get the stream reference
    let stream_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(Some(EmValue::I32(-1))),
    };

    // Read a single byte from the stream (advances position internally)
    let Some(byte) = try_hook!(thread.heap().stream_read_byte(stream_ref)) else {
        return PreHookResult::Bypass(Some(EmValue::I32(-1))); // EOF or not a stream
    };

    PreHookResult::Bypass(Some(EmValue::I32(i32::from(byte))))
}

/// Hook for `System.IO.MemoryStream.Write` method.
///
/// # Handled Overloads
///
/// - `MemoryStream.Write(Byte[], Int32, Int32) -> Void`
///
/// # Parameters
///
/// - `buffer`: Source byte array containing data to write
/// - `offset`: Zero-based byte offset in buffer from which to copy bytes
/// - `count`: Number of bytes to write
fn stream_write_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    // Get the stream reference
    let stream_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(None),
    };

    // Parse arguments: buffer, offset, count
    // Safe: values validated as non-negative
    #[allow(clippy::cast_sign_loss)]
    let (buffer_ref, offset, count) = match (ctx.args.first(), ctx.args.get(1), ctx.args.get(2)) {
        (Some(EmValue::ObjectRef(b)), Some(EmValue::I32(o)), Some(EmValue::I32(c))) => {
            (*b, *o as usize, *c as usize)
        }
        _ => return PreHookResult::Bypass(None),
    };

    // Get bytes from the buffer array
    let Some(buffer_data) = try_hook!(thread.heap().get_byte_array(buffer_ref)) else {
        return PreHookResult::Bypass(None);
    };

    // Extract the slice to write
    let end = (offset + count).min(buffer_data.len());
    let bytes_to_write = if offset < buffer_data.len() {
        &buffer_data[offset..end]
    } else {
        &[]
    };

    // Write to the stream
    try_hook!(thread
        .heap_mut()
        .write_to_stream(stream_ref, bytes_to_write));

    PreHookResult::Bypass(None)
}

/// Hook for `System.IO.MemoryStream.ToArray` method.
///
/// # Handled Overloads
///
/// - `MemoryStream.ToArray() -> Byte[]`
///
/// # Returns
///
/// A new byte array containing the stream contents
fn memory_stream_to_array_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    // Get the stream reference
    let stream_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => {
            // Return empty byte array if no stream
            match thread.heap_mut().alloc_byte_array(&[]) {
                Ok(array_ref) => return PreHookResult::Bypass(Some(EmValue::ObjectRef(array_ref))),
                Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
            }
        }
    };

    // ToArray needs the full buffer — clone is unavoidable here
    let data = match try_hook!(thread.heap().get_stream_data(stream_ref)) {
        Some((data, _)) => data,
        None => Vec::new(),
    };

    // Allocate and return byte array
    match thread.heap_mut().alloc_byte_array(&data) {
        Ok(array_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(array_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.IO.Stream.get_Length` and `System.IO.MemoryStream.get_Length` properties.
///
/// # Handled Overloads
///
/// - `Stream.Length { get; } -> Int64`
/// - `MemoryStream.Length { get; } -> Int64`
///
/// # Returns
///
/// The length of the stream in bytes
fn stream_get_length_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    // Get the stream reference
    let stream_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        Some(EmValue::Null) => return PreHookResult::throw_null_reference(),
        _ => return PreHookResult::throw_object_disposed(),
    };

    // Get stream length without cloning data
    let length = try_hook!(thread.heap().stream_len(stream_ref)).unwrap_or(0);

    #[allow(clippy::cast_possible_wrap)]
    PreHookResult::Bypass(Some(EmValue::I64(length as i64)))
}

/// Hook for `System.IO.MemoryStream.get_Position` property.
///
/// # Handled Overloads
///
/// - `MemoryStream.Position { get; } -> Int64`
///
/// # Returns
///
/// The current position within the stream
fn stream_get_position_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    // Get the stream reference
    let stream_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        Some(EmValue::Null) => return PreHookResult::throw_null_reference(),
        _ => return PreHookResult::throw_object_disposed(),
    };

    // Get stream position without cloning data
    let position = try_hook!(thread.heap().stream_position(stream_ref)).unwrap_or(0);

    #[allow(clippy::cast_possible_wrap)]
    PreHookResult::Bypass(Some(EmValue::I64(position as i64)))
}

/// Hook for `System.IO.MemoryStream.set_Position` property.
///
/// # Handled Overloads
///
/// - `MemoryStream.Position { set; }`
///
/// # Parameters
///
/// - `value`: The new position within the stream
fn stream_set_position_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    // Get the stream reference
    let stream_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(None),
    };

    // Get the new position
    // Safe: values validated as non-negative
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let new_pos = match ctx.args.first() {
        Some(EmValue::I64(v)) => *v as usize,
        Some(EmValue::I32(v)) => *v as usize,
        _ => return PreHookResult::Bypass(None),
    };

    // Update stream position
    try_hook!(thread.heap_mut().set_stream_position(stream_ref, new_pos));
    PreHookResult::Bypass(None)
}

/// Hook for `System.IO.MemoryStream.Seek` method.
///
/// # Handled Overloads
///
/// - `MemoryStream.Seek(Int64, SeekOrigin) -> Int64`
///
/// # Parameters
///
/// - `offset`: Byte offset relative to origin
/// - `origin`: Reference point (Begin=0, Current=1, End=2)
///
/// # Returns
///
/// The new position within the stream
fn stream_seek_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    // Get the stream reference
    let stream_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        Some(EmValue::Null) => return PreHookResult::throw_null_reference(),
        _ => return PreHookResult::throw_object_disposed(),
    };

    // Get offset and origin
    let offset = match ctx.args.first() {
        Some(EmValue::I64(v)) => *v,
        Some(EmValue::I32(v)) => i64::from(*v),
        _ => 0,
    };

    let origin = match ctx.args.get(1) {
        Some(EmValue::I32(v)) => *v,
        _ => 0, // Default to Begin
    };

    // Get stream length and position without cloning data
    let Some(length) = try_hook!(thread.heap().stream_len(stream_ref)) else {
        return PreHookResult::Bypass(Some(EmValue::I64(0)));
    };
    let current_pos = try_hook!(thread.heap().stream_position(stream_ref)).unwrap_or(0);

    // Calculate new position based on origin
    // SeekOrigin: 0=Begin, 1=Current, 2=End
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let new_pos = match origin {
        1 => {
            // Current
            // Safe: stream positions fit in i64
            #[allow(clippy::cast_possible_wrap)]
            let pos = current_pos as i64 + offset;
            pos.max(0) as usize
        }
        2 => {
            // End
            // Safe: stream positions fit in i64
            #[allow(clippy::cast_possible_wrap)]
            let pos = length as i64 + offset;
            pos.max(0) as usize
        }
        // Begin (0) and default
        _ => offset.max(0) as usize,
    };

    // Clamp to valid range
    let clamped_pos = new_pos.min(length);

    // Update stream position
    try_hook!(thread
        .heap_mut()
        .set_stream_position(stream_ref, clamped_pos));

    #[allow(clippy::cast_possible_wrap)]
    PreHookResult::Bypass(Some(EmValue::I64(clamped_pos as i64)))
}

/// Hook for `System.IO.Stream.WriteByte` and `System.IO.MemoryStream.WriteByte` methods.
///
/// # Handled Overloads
///
/// - `Stream.WriteByte(Byte) -> Void`
/// - `MemoryStream.WriteByte(Byte) -> Void`
///
/// # Parameters
///
/// - `value`: The byte to write
fn stream_write_byte_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let stream_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(None),
    };

    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    let byte = match ctx.args.first() {
        Some(EmValue::I32(v)) => *v as u8,
        _ => return PreHookResult::Bypass(None),
    };

    try_hook!(thread.heap_mut().write_to_stream(stream_ref, &[byte]));
    PreHookResult::Bypass(None)
}

/// Hook for `System.IO.MemoryStream.GetBuffer` method.
///
/// # Handled Overloads
///
/// - `MemoryStream.GetBuffer() -> Byte[]`
///
/// # Returns
///
/// The internal byte array buffer of the stream
fn memory_stream_get_buffer_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    // Identical to ToArray — return all stream data as a byte array
    memory_stream_to_array_pre(ctx, thread)
}

/// Hook for `System.IO.Stream.SetLength` and `System.IO.MemoryStream.SetLength` methods.
///
/// # Handled Overloads
///
/// - `Stream.SetLength(Int64) -> Void`
/// - `MemoryStream.SetLength(Int64) -> Void`
///
/// # Parameters
///
/// - `value`: The new length of the stream
fn stream_set_length_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let stream_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(None),
    };

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let new_length = match ctx.args.first() {
        Some(EmValue::I64(v)) => *v as usize,
        Some(EmValue::I32(v)) => *v as usize,
        _ => return PreHookResult::Bypass(None),
    };

    try_hook!(thread.heap_mut().truncate_stream(stream_ref, new_length));
    PreHookResult::Bypass(None)
}

/// Hook for `System.IO.Stream.CopyTo` and `System.IO.MemoryStream.CopyTo` methods.
///
/// # Handled Overloads
///
/// - `Stream.CopyTo(Stream) -> Void`
/// - `Stream.CopyTo(Stream, Int32) -> Void`
/// - `MemoryStream.CopyTo(Stream) -> Void`
/// - `MemoryStream.CopyTo(Stream, Int32) -> Void`
///
/// # Parameters
///
/// - `destination`: The target stream to copy data to
/// - `bufferSize`: (optional) ignored
fn stream_copy_to_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let src_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(None),
    };

    let dst_ref = match ctx.args.first() {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(None),
    };

    // Plain `MemoryStream` / `Stream` source. Fast path that mirrors the
    // original CopyTo behavior — read remaining bytes, advance position.
    if let Some((data, position)) = try_hook!(thread.heap().get_stream_data(src_ref)) {
        if position < data.len() {
            let remaining = &data[position..];
            try_hook!(thread.heap_mut().write_to_stream(dst_ref, remaining));
        }
        let len = data.len();
        try_hook!(thread.heap_mut().set_stream_position(src_ref, len));
        return PreHookResult::Bypass(None);
    }

    // `DeflateStream` / `GZipStream` source. Decompress the underlying
    // stream the same way `compressed_stream_read_pre` does, then drain
    // the cached buffer into the destination. Without this branch a CFF
    // dispatcher pattern like `MemoryStream(enc) -> DeflateStream ->
    // CopyTo(MemoryStream)` ends up writing nothing because the original
    // `get_stream_data` only matched `HeapObject::Stream`.
    if let Some((underlying, compression_type, _mode)) =
        try_hook!(thread.heap().get_compressed_stream_info(src_ref))
    {
        if !try_hook!(thread.heap().has_compressed_stream_data(src_ref)) {
            let Some((compressed_data, underlying_pos)) =
                try_hook!(thread.heap().get_stream_data(underlying))
            else {
                return PreHookResult::Bypass(None);
            };
            let effective = if underlying_pos < compressed_data.len() {
                &compressed_data[underlying_pos..]
            } else {
                &[]
            };
            let decompressed = match compression_type {
                0 => decompress_deflate(effective).ok(),
                1 => decompress_gzip(effective).ok(),
                _ => None,
            };
            try_hook!(thread
                .heap()
                .set_compressed_stream_data(src_ref, decompressed.unwrap_or_default()));
        }
        let Some(bytes) = try_hook!(thread.heap().read_compressed_stream(src_ref, usize::MAX))
        else {
            return PreHookResult::Bypass(None);
        };
        if !bytes.is_empty() {
            try_hook!(thread.heap_mut().write_to_stream(dst_ref, &bytes));
        }
        return PreHookResult::Bypass(None);
    }

    // `CryptoStream` source. Lazily transform the underlying buffer once,
    // then drain. Mirrors `crypto_stream_read_pre` so behaviour matches
    // whether the caller does `CopyTo` or repeated `Read`s.
    if let Some((underlying, transform, _mode)) =
        try_hook!(thread.heap().get_crypto_stream_info(src_ref))
    {
        if try_hook!(thread.heap().get_crypto_stream_transformed(src_ref)).is_none() {
            let Some((stream_data, underlying_pos)) =
                try_hook!(thread.heap().get_stream_data(underlying))
            else {
                return PreHookResult::Bypass(None);
            };
            let effective = if underlying_pos < stream_data.len() {
                &stream_data[underlying_pos..]
            } else {
                &[]
            };
            let transformed = if let Some((algorithm, key, iv, is_encryptor, cmode, padding)) =
                try_hook!(thread.heap().get_crypto_transform_info(transform))
            {
                apply_crypto_transform(
                    &algorithm,
                    &key,
                    &iv,
                    is_encryptor,
                    effective,
                    cmode,
                    padding,
                )
                .unwrap_or_else(|| effective.to_vec())
            } else {
                effective.to_vec()
            };
            try_hook!(thread
                .heap()
                .set_crypto_stream_transformed(src_ref, transformed));
        }
        let Some(bytes) = try_hook!(thread.heap().read_crypto_stream(src_ref, usize::MAX)) else {
            return PreHookResult::Bypass(None);
        };
        if !bytes.is_empty() {
            try_hook!(thread.heap_mut().write_to_stream(dst_ref, &bytes));
        }
        return PreHookResult::Bypass(None);
    }

    // Unknown stream subclass — leave the destination untouched rather
    // than guess at a backing store.
    PreHookResult::Bypass(None)
}

/// Hook for `Stream.get_CanRead`, `Stream.get_CanSeek`, `Stream.get_CanWrite` properties.
///
/// Emulated streams always support all operations.
pub(crate) fn stream_can_true_pre(
    _ctx: &HookContext<'_>,
    _thread: &mut EmulationThread,
) -> PreHookResult {
    PreHookResult::Bypass(Some(EmValue::I32(1)))
}

/// Hook for `System.IO.Stream.Close` and related `Close` methods.
///
/// # Handled Overloads
///
/// - `Stream.Close() -> Void`
///
/// # Implementation Note
///
/// This is a no-op as emulated streams do not require cleanup.
pub(crate) fn stream_close_pre(
    _ctx: &HookContext<'_>,
    _thread: &mut EmulationThread,
) -> PreHookResult {
    PreHookResult::Bypass(None)
}

/// Hook for `System.IO.Stream.Dispose` and related `Dispose` methods.
///
/// # Handled Overloads
///
/// - `Stream.Dispose() -> Void`
///
/// # Implementation Note
///
/// This is a no-op as emulated streams do not require cleanup.
pub(crate) fn stream_dispose_pre(
    _ctx: &HookContext<'_>,
    _thread: &mut EmulationThread,
) -> PreHookResult {
    PreHookResult::Bypass(None)
}

#[cfg(test)]
mod tests {
    use crate::{
        emulation::{
            runtime::{
                bcl::io::stream::{
                    memory_stream_ctor_pre, memory_stream_to_array_pre, stream_close_pre,
                    stream_get_length_pre, stream_get_position_pre, stream_read_byte_pre,
                    stream_seek_pre, stream_set_position_pre,
                },
                hook::{HookContext, HookManager, PreHookResult},
            },
            EmValue,
        },
        metadata::{token::Token, typesystem::PointerSize},
        test::emulation::create_test_thread,
    };

    #[test]
    fn test_register_hooks() {
        let manager = HookManager::new();
        super::register(&manager).unwrap();
        assert_eq!(manager.len(), 36);
    }

    #[test]
    fn test_stream_close_hook() {
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "Stream",
            "Close",
            PointerSize::Bit64,
        );

        let mut thread = create_test_thread();
        let result = stream_close_pre(&ctx, &mut thread);

        match result {
            PreHookResult::Bypass(None) => {}
            _ => panic!("Expected Bypass(None)"),
        }
    }

    #[test]
    fn test_stream_read_byte_eof_without_stream() {
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "Stream",
            "ReadByte",
            PointerSize::Bit64,
        );

        let mut thread = create_test_thread();
        let result = stream_read_byte_pre(&ctx, &mut thread);

        match result {
            PreHookResult::Bypass(Some(EmValue::I32(-1))) => {}
            _ => panic!("Expected Bypass with I32(-1) for EOF"),
        }
    }

    #[test]
    fn test_stream_read_byte_with_data() {
        let mut thread = create_test_thread();

        // Create a stream with test data
        let data = vec![1, 2, 3, 4, 5];
        let stream_ref = thread.heap_mut().alloc_stream(data, None).unwrap();

        let this = EmValue::ObjectRef(stream_ref);
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "Stream",
            "ReadByte",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));

        // Read first byte
        let result = stream_read_byte_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(1)))
        ));

        // Read second byte
        let result = stream_read_byte_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(2)))
        ));

        // Read remaining bytes
        for expected in [3, 4, 5] {
            let result = stream_read_byte_pre(&ctx, &mut thread);
            assert!(
                matches!(result, PreHookResult::Bypass(Some(EmValue::I32(v))) if v == expected)
            );
        }

        // After all bytes, should return EOF
        let result = stream_read_byte_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(-1)))
        ));
    }

    #[test]
    fn test_stream_get_length_hook() {
        let mut thread = create_test_thread();

        let data = vec![1, 2, 3, 4, 5];
        let stream_ref = thread.heap_mut().alloc_stream(data, None).unwrap();

        let this = EmValue::ObjectRef(stream_ref);
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "Stream",
            "get_Length",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));

        let result = stream_get_length_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I64(5)))
        ));
    }

    #[test]
    fn test_stream_get_position_hook() {
        let mut thread = create_test_thread();

        let data = vec![1, 2, 3, 4, 5];
        let stream_ref = thread.heap_mut().alloc_stream(data, None).unwrap();

        let this = EmValue::ObjectRef(stream_ref);
        let get_pos_ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "Stream",
            "get_Position",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));
        let read_byte_ctx = HookContext::new(
            Token::new(0x0A000002),
            "System.IO",
            "Stream",
            "ReadByte",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));

        // Initial position is 0
        let result = stream_get_position_pre(&get_pos_ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I64(0)))
        ));

        // Read a byte, position should advance
        stream_read_byte_pre(&read_byte_ctx, &mut thread);

        let result = stream_get_position_pre(&get_pos_ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I64(1)))
        ));
    }

    #[test]
    fn test_stream_set_position_hook() {
        let mut thread = create_test_thread();

        let data = vec![1, 2, 3, 4, 5];
        let stream_ref = thread.heap_mut().alloc_stream(data, None).unwrap();

        let this = EmValue::ObjectRef(stream_ref);
        let args = [EmValue::I64(3)];
        let set_pos_ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "Stream",
            "set_Position",
            PointerSize::Bit64,
        )
        .with_this(Some(&this))
        .with_args(&args);

        // Set position to 3
        stream_set_position_pre(&set_pos_ctx, &mut thread);

        // Verify position
        let get_pos_ctx = HookContext::new(
            Token::new(0x0A000002),
            "System.IO",
            "Stream",
            "get_Position",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));
        let result = stream_get_position_pre(&get_pos_ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I64(3)))
        ));

        // Read byte at position 3 (value should be 4)
        let read_byte_ctx = HookContext::new(
            Token::new(0x0A000003),
            "System.IO",
            "Stream",
            "ReadByte",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));
        let result = stream_read_byte_pre(&read_byte_ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(4)))
        ));
    }

    #[test]
    fn test_memory_stream_to_array_hook() {
        let mut thread = create_test_thread();

        let data = vec![10, 20, 30];
        let stream_ref = thread.heap_mut().alloc_stream(data.clone(), None).unwrap();

        let this = EmValue::ObjectRef(stream_ref);
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "MemoryStream",
            "ToArray",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));

        let result = memory_stream_to_array_pre(&ctx, &mut thread);

        // Verify we get an array back
        let array_ref = match result {
            PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) => r,
            _ => panic!("Expected Bypass with ObjectRef"),
        };

        // Verify array contents
        let retrieved = thread.heap().get_byte_array(array_ref).unwrap().unwrap();
        assert_eq!(retrieved.as_slice(), &[10, 20, 30]);
    }

    #[test]
    fn test_memory_stream_ctor_hook() {
        let mut thread = create_test_thread();

        // Create source byte array
        let data = vec![1, 2, 3, 4, 5];
        let array_ref = thread.heap_mut().alloc_byte_array(&data).unwrap();

        // Call constructor (factory pattern)
        let args = [EmValue::ObjectRef(array_ref)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "MemoryStream",
            ".ctor",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let result = memory_stream_ctor_pre(&ctx, &mut thread);

        let stream_ref = match result {
            PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) => r,
            _ => panic!("Expected Bypass with ObjectRef"),
        };

        // Verify stream has correct length
        let this = EmValue::ObjectRef(stream_ref);
        let length_ctx = HookContext::new(
            Token::new(0x0A000002),
            "System.IO",
            "MemoryStream",
            "get_Length",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));

        let result = stream_get_length_pre(&length_ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I64(5)))
        ));

        // Verify we can read data
        let read_ctx = HookContext::new(
            Token::new(0x0A000003),
            "System.IO",
            "MemoryStream",
            "ReadByte",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));
        let result = stream_read_byte_pre(&read_ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(1)))
        ));
    }

    #[test]
    fn test_stream_seek_hook() {
        let mut thread = create_test_thread();

        let data = vec![10, 20, 30, 40, 50];
        let stream_ref = thread.heap_mut().alloc_stream(data, None).unwrap();

        let this = EmValue::ObjectRef(stream_ref);

        // Seek to position 2 from beginning (origin = 0)
        let args = [EmValue::I64(2), EmValue::I32(0)];
        let seek_ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "MemoryStream",
            "Seek",
            PointerSize::Bit64,
        )
        .with_this(Some(&this))
        .with_args(&args);

        let result = stream_seek_pre(&seek_ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I64(2)))
        ));

        // Read byte at position 2 (value should be 30)
        let read_ctx = HookContext::new(
            Token::new(0x0A000002),
            "System.IO",
            "MemoryStream",
            "ReadByte",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));
        let result = stream_read_byte_pre(&read_ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(30)))
        ));

        // Seek to end (origin = 2) with offset -1
        let args = [EmValue::I64(-1), EmValue::I32(2)];
        let seek_ctx = HookContext::new(
            Token::new(0x0A000003),
            "System.IO",
            "MemoryStream",
            "Seek",
            PointerSize::Bit64,
        )
        .with_this(Some(&this))
        .with_args(&args);

        let result = stream_seek_pre(&seek_ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I64(4)))
        ));

        // Read last byte (value should be 50)
        let result = stream_read_byte_pre(&read_ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(50)))
        ));
    }
}
