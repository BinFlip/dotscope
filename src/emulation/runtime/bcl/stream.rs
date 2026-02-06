//! `System.IO.Stream`, `MemoryStream`, and `BinaryReader` method hooks.
//!
//! This module provides hook implementations for stream-related classes used by
//! obfuscators for reading embedded data, decompressing payloads, and processing
//! encrypted content. Streams are backed by [`HeapObject::Stream`] for full data
//! tracking and position management.
//!
//! # Overview
//!
//! Stream classes are fundamental to .NET I/O operations. Obfuscators commonly use
//! `MemoryStream` to wrap byte arrays and `BinaryReader` to parse structured data.
//! These hooks provide functional implementations that store and retrieve actual data.
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
//! | `MemoryStream.Write(byte[], int, int)` | Write bytes | No-op (read-only streams) |
//! | `MemoryStream.ToArray()` | Get stream contents | Returns full Stream data as byte array |
//! | `MemoryStream.get_Length` | Stream length | Returns actual data length |
//! | `MemoryStream.get_Position` | Current position | Returns current read position |
//! | `MemoryStream.set_Position` | Set position | Updates stream position |
//! | `MemoryStream.Seek(long, SeekOrigin)` | Seek to position | Updates position based on origin |
//!
//! ## Stream Base Class Methods
//!
//! | Method | Description | Implementation |
//! |--------|-------------|----------------|
//! | `Stream.Read(byte[], int, int)` | Read bytes | Reads from Stream data |
//! | `Stream.ReadByte()` | Read single byte | Reads byte from Stream |
//! | `Stream.get_Length` | Stream length | Returns actual length |
//! | `Stream.Close()` | Close stream | No-op |
//! | `Stream.Dispose()` | Dispose stream | No-op |
//!
//! ## BinaryReader Methods
//!
//! | Method | Description | Implementation |
//! |--------|-------------|----------------|
//! | `BinaryReader..ctor(Stream)` | Create reader | Stores stream reference in synthetic field |
//! | `BinaryReader.ReadByte()` | Read byte | Reads from stream, advances position |
//! | `BinaryReader.ReadBytes(int)` | Read byte array | Reads from stream, advances position |
//! | `BinaryReader.ReadInt16()` | Read 16-bit int | Reads little-endian from stream |
//! | `BinaryReader.ReadInt32()` | Read 32-bit int | Reads little-endian from stream |
//! | `BinaryReader.ReadInt64()` | Read 64-bit int | Reads little-endian from stream |
//! | `BinaryReader.ReadString()` | Read length-prefixed string | Reads 7-bit length + UTF-8 bytes |
//! | `BinaryReader.Close()` | Close reader | No-op |
//!
//! # Deobfuscation Use Cases
//!
//! ## Payload Decompression
//!
//! Obfuscators often embed compressed data and decompress at runtime:
//!
//! ```csharp
//! byte[] compressed = GetEmbeddedResource();
//! using (MemoryStream ms = new MemoryStream(compressed))
//! using (DeflateStream ds = new DeflateStream(ms, CompressionMode.Decompress))
//! {
//!     byte[] payload = ReadAll(ds);
//!     Assembly.Load(payload);
//! }
//! ```
//!
//! ## Structured Data Parsing
//!
//! Encrypted string tables are often read with `BinaryReader`:
//!
//! ```csharp
//! using (BinaryReader reader = new BinaryReader(ms))
//! {
//!     int count = reader.ReadInt32();
//!     for (int i = 0; i < count; i++)
//!     {
//!         string s = reader.ReadString();
//!         // Process decrypted string...
//!     }
//! }
//! ```
//!
//! # Implementation Notes
//!
//! Stream data is stored in [`HeapObject::Stream`] which provides:
//!
//! - **Full data tracking**: Stream contents are stored and retrieved correctly
//! - **Position tracking**: Read position advances as data is consumed
//! - **Length tracking**: Actual data length is available
//! - **Read-only**: Write operations are no-ops (sufficient for deobfuscation)
//!
//! [`HeapObject::Stream`]: crate::emulation::memory::HeapObject::Stream

use crate::{
    emulation::{
        runtime::hook::{Hook, HookContext, HookManager, PreHookResult},
        thread::EmulationThread,
        EmValue, HeapRef,
    },
    metadata::token::Token,
};

/// Returns the synthetic field token used to store the underlying stream reference in BinaryReader.
/// Uses a high value to avoid collision with real field tokens.
fn binary_reader_stream_field() -> Token {
    Token::new(0xFFFF_0001)
}

/// Registers all Stream and BinaryReader method hooks with the given hook manager.
///
/// # Arguments
///
/// * `manager` - The [`HookManager`] to register hooks with
///
/// # Registered Hooks
///
/// ## MemoryStream
/// - `MemoryStream..ctor(byte[])`
/// - `MemoryStream.Read`, `MemoryStream.ReadByte`, `MemoryStream.Write`
/// - `MemoryStream.ToArray`, `MemoryStream.get_Length`
/// - `MemoryStream.get_Position`, `MemoryStream.set_Position`, `MemoryStream.Seek`
///
/// ## Stream
/// - `Stream.Read`, `Stream.ReadByte`, `Stream.get_Length`
/// - `Stream.Close`, `Stream.Dispose`
///
/// ## BinaryReader
/// - `BinaryReader..ctor(Stream)`
/// - `BinaryReader.ReadByte`, `BinaryReader.ReadBytes`
/// - `BinaryReader.ReadInt16`, `BinaryReader.ReadInt32`, `BinaryReader.ReadInt64`
/// - `BinaryReader.ReadString`, `BinaryReader.Close`
pub fn register(manager: &mut HookManager) {
    // MemoryStream methods
    manager.register(
        Hook::new("System.IO.MemoryStream..ctor")
            .match_name("System.IO", "MemoryStream", ".ctor")
            .pre(memory_stream_ctor_pre),
    );

    manager.register(
        Hook::new("System.IO.MemoryStream.Read")
            .match_name("System.IO", "MemoryStream", "Read")
            .pre(stream_read_pre),
    );

    manager.register(
        Hook::new("System.IO.MemoryStream.ReadByte")
            .match_name("System.IO", "MemoryStream", "ReadByte")
            .pre(stream_read_byte_pre),
    );

    manager.register(
        Hook::new("System.IO.MemoryStream.Write")
            .match_name("System.IO", "MemoryStream", "Write")
            .pre(stream_write_pre),
    );

    manager.register(
        Hook::new("System.IO.MemoryStream.ToArray")
            .match_name("System.IO", "MemoryStream", "ToArray")
            .pre(memory_stream_to_array_pre),
    );

    manager.register(
        Hook::new("System.IO.MemoryStream.get_Length")
            .match_name("System.IO", "MemoryStream", "get_Length")
            .pre(stream_get_length_pre),
    );

    manager.register(
        Hook::new("System.IO.MemoryStream.get_Position")
            .match_name("System.IO", "MemoryStream", "get_Position")
            .pre(stream_get_position_pre),
    );

    manager.register(
        Hook::new("System.IO.MemoryStream.set_Position")
            .match_name("System.IO", "MemoryStream", "set_Position")
            .pre(stream_set_position_pre),
    );

    manager.register(
        Hook::new("System.IO.MemoryStream.Seek")
            .match_name("System.IO", "MemoryStream", "Seek")
            .pre(stream_seek_pre),
    );

    // Stream base class methods
    manager.register(
        Hook::new("System.IO.Stream.Read")
            .match_name("System.IO", "Stream", "Read")
            .pre(stream_read_pre),
    );

    manager.register(
        Hook::new("System.IO.Stream.ReadByte")
            .match_name("System.IO", "Stream", "ReadByte")
            .pre(stream_read_byte_pre),
    );

    manager.register(
        Hook::new("System.IO.Stream.get_Length")
            .match_name("System.IO", "Stream", "get_Length")
            .pre(stream_get_length_pre),
    );

    manager.register(
        Hook::new("System.IO.Stream.Close")
            .match_name("System.IO", "Stream", "Close")
            .pre(stream_close_pre),
    );

    manager.register(
        Hook::new("System.IO.Stream.Dispose")
            .match_name("System.IO", "Stream", "Dispose")
            .pre(stream_dispose_pre),
    );

    // BinaryReader methods
    manager.register(
        Hook::new("System.IO.BinaryReader..ctor")
            .match_name("System.IO", "BinaryReader", ".ctor")
            .pre(binary_reader_ctor_pre),
    );

    manager.register(
        Hook::new("System.IO.BinaryReader.ReadByte")
            .match_name("System.IO", "BinaryReader", "ReadByte")
            .pre(binary_reader_read_byte_pre),
    );

    manager.register(
        Hook::new("System.IO.BinaryReader.ReadBytes")
            .match_name("System.IO", "BinaryReader", "ReadBytes")
            .pre(binary_reader_read_bytes_pre),
    );

    manager.register(
        Hook::new("System.IO.BinaryReader.ReadInt16")
            .match_name("System.IO", "BinaryReader", "ReadInt16")
            .pre(binary_reader_read_int16_pre),
    );

    manager.register(
        Hook::new("System.IO.BinaryReader.ReadInt32")
            .match_name("System.IO", "BinaryReader", "ReadInt32")
            .pre(binary_reader_read_int32_pre),
    );

    manager.register(
        Hook::new("System.IO.BinaryReader.ReadInt64")
            .match_name("System.IO", "BinaryReader", "ReadInt64")
            .pre(binary_reader_read_int64_pre),
    );

    manager.register(
        Hook::new("System.IO.BinaryReader.ReadString")
            .match_name("System.IO", "BinaryReader", "ReadString")
            .pre(binary_reader_read_string_pre),
    );

    manager.register(
        Hook::new("System.IO.BinaryReader.Close")
            .match_name("System.IO", "BinaryReader", "Close")
            .pre(stream_close_pre),
    );
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
        thread
            .heap()
            .get_byte_array(*array_ref)
            .or_else(|| thread.heap().get_array_as_bytes(*array_ref))
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    match ctx.this {
        Some(EmValue::ObjectRef(stream_ref)) => {
            // Instance call: replace the allocated object with a Stream
            thread.heap_mut().replace_with_stream(*stream_ref, data);
            PreHookResult::Bypass(None) // Constructor returns void
        }
        _ => {
            // Factory pattern: allocate a new Stream directly
            match thread.heap_mut().alloc_stream(data) {
                Ok(stream_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(stream_ref))),
                Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
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
        _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
    };

    // Parse arguments: buffer, offset, count
    let (buffer_ref, offset, count) = match (ctx.args.first(), ctx.args.get(1), ctx.args.get(2)) {
        (Some(EmValue::ObjectRef(b)), Some(EmValue::I32(o)), Some(EmValue::I32(c))) => {
            (*b, *o as usize, *c as usize)
        }
        _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
    };

    // Get stream data and position
    let Some((data, position)) = thread.heap().get_stream_data(stream_ref) else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    // Calculate how many bytes we can read
    let available = data.len().saturating_sub(position);
    let to_read = count.min(available);

    // Read bytes into buffer
    for i in 0..to_read {
        if let Some(&byte) = data.get(position + i) {
            let _ = thread.heap_mut().set_array_element(
                buffer_ref,
                offset + i,
                EmValue::I32(i32::from(byte)),
            );
        }
    }

    // Update stream position
    thread
        .heap_mut()
        .set_stream_position(stream_ref, position + to_read);

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

    // Get stream data and position
    let Some((data, position)) = thread.heap().get_stream_data(stream_ref) else {
        return PreHookResult::Bypass(Some(EmValue::I32(-1)));
    };

    // Check if at end of stream
    if position >= data.len() {
        return PreHookResult::Bypass(Some(EmValue::I32(-1))); // EOF
    }

    // Read the byte
    let byte = data[position];

    // Update stream position
    thread
        .heap_mut()
        .set_stream_position(stream_ref, position + 1);

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
    let (buffer_ref, offset, count) = match (ctx.args.first(), ctx.args.get(1), ctx.args.get(2)) {
        (Some(EmValue::ObjectRef(b)), Some(EmValue::I32(o)), Some(EmValue::I32(c))) => {
            (*b, *o as usize, *c as usize)
        }
        _ => return PreHookResult::Bypass(None),
    };

    // Get bytes from the buffer array
    let Some(buffer_data) = thread.heap().get_byte_array(buffer_ref) else {
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
    thread
        .heap_mut()
        .write_to_stream(stream_ref, bytes_to_write);

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
                Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
            }
        }
    };

    // Get stream data (already cloned by get_stream_data)
    let data = match thread.heap().get_stream_data(stream_ref) {
        Some((data, _)) => data,
        None => Vec::new(),
    };

    // Allocate and return byte array
    match thread.heap_mut().alloc_byte_array(&data) {
        Ok(array_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(array_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
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
        _ => return PreHookResult::Bypass(Some(EmValue::I64(0))),
    };

    // Get stream data length
    let length = match thread.heap().get_stream_data(stream_ref) {
        Some((data, _)) => data.len(),
        None => 0,
    };

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
        _ => return PreHookResult::Bypass(Some(EmValue::I64(0))),
    };

    // Get stream position
    let position = match thread.heap().get_stream_data(stream_ref) {
        Some((_, pos)) => pos,
        None => 0,
    };

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
    let new_pos = match ctx.args.first() {
        Some(EmValue::I64(v)) => *v as usize,
        Some(EmValue::I32(v)) => *v as usize,
        _ => return PreHookResult::Bypass(None),
    };

    // Update stream position
    thread.heap_mut().set_stream_position(stream_ref, new_pos);
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
        _ => return PreHookResult::Bypass(Some(EmValue::I64(0))),
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

    // Get current stream data for length and position
    let (length, current_pos) = match thread.heap().get_stream_data(stream_ref) {
        Some((data, pos)) => (data.len(), pos),
        None => return PreHookResult::Bypass(Some(EmValue::I64(0))),
    };

    // Calculate new position based on origin
    // SeekOrigin: 0=Begin, 1=Current, 2=End
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let new_pos = match origin {
        0 => offset.max(0) as usize, // Begin
        1 => {
            // Current
            let pos = current_pos as i64 + offset;
            pos.max(0) as usize
        }
        2 => {
            // End
            let pos = length as i64 + offset;
            pos.max(0) as usize
        }
        _ => offset.max(0) as usize, // Default to Begin
    };

    // Clamp to valid range
    let clamped_pos = new_pos.min(length);

    // Update stream position
    thread
        .heap_mut()
        .set_stream_position(stream_ref, clamped_pos);

    #[allow(clippy::cast_possible_wrap)]
    PreHookResult::Bypass(Some(EmValue::I64(clamped_pos as i64)))
}

/// Hook for `System.IO.Stream.Close` and `System.IO.BinaryReader.Close` methods.
///
/// # Handled Overloads
///
/// - `Stream.Close() -> Void`
/// - `BinaryReader.Close() -> Void`
///
/// # Implementation Note
///
/// This is a no-op as emulated streams do not require cleanup.
fn stream_close_pre(_ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    PreHookResult::Bypass(None)
}

/// Hook for `System.IO.Stream.Dispose` method.
///
/// # Handled Overloads
///
/// - `Stream.Dispose() -> Void`
///
/// # Implementation Note
///
/// This is a no-op as emulated streams do not require cleanup.
fn stream_dispose_pre(_ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    PreHookResult::Bypass(None)
}

/// Helper function to get the underlying stream reference from a BinaryReader.
fn get_binary_reader_stream(reader_ref: HeapRef, thread: &EmulationThread) -> Option<HeapRef> {
    let field_value = thread
        .heap()
        .get_field(reader_ref, binary_reader_stream_field())
        .ok()?;
    match field_value {
        EmValue::ObjectRef(stream_ref) => Some(stream_ref),
        _ => None,
    }
}

/// Hook for `System.IO.BinaryReader..ctor` constructor.
///
/// # Handled Overloads
///
/// - `BinaryReader..ctor(Stream)`
///
/// # Parameters
///
/// - `input`: The underlying stream to read from
fn binary_reader_ctor_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    // Get the BinaryReader object reference
    let reader_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(None),
    };

    // Get the stream argument
    let stream_ref = match ctx.args.first() {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(None),
    };

    // Store the stream reference in the BinaryReader's field
    let _ = thread.heap_mut().set_field(
        reader_ref,
        binary_reader_stream_field(),
        EmValue::ObjectRef(stream_ref),
    );

    PreHookResult::Bypass(None)
}

/// Hook for `System.IO.BinaryReader.ReadByte` method.
///
/// # Handled Overloads
///
/// - `BinaryReader.ReadByte() -> Byte`
///
/// # Returns
///
/// The next byte read from the underlying stream
fn binary_reader_read_byte_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    // Get the BinaryReader object reference
    let reader_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
    };

    // Get the underlying stream
    let Some(stream_ref) = get_binary_reader_stream(reader_ref, thread) else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    // Get stream data and position
    let Some((data, position)) = thread.heap().get_stream_data(stream_ref) else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    // Check if at end of stream
    if position >= data.len() {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    }

    // Read the byte
    let byte = data[position];

    // Update stream position
    thread
        .heap_mut()
        .set_stream_position(stream_ref, position + 1);

    PreHookResult::Bypass(Some(EmValue::I32(i32::from(byte))))
}

/// Hook for `System.IO.BinaryReader.ReadBytes` method.
///
/// # Handled Overloads
///
/// - `BinaryReader.ReadBytes(Int32) -> Byte[]`
///
/// # Parameters
///
/// - `count`: Number of bytes to read
///
/// # Returns
///
/// A byte array containing the requested bytes
fn binary_reader_read_bytes_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let count = match ctx.args.first() {
        Some(EmValue::I32(v)) => *v as usize,
        _ => 0,
    };

    // Get the BinaryReader object reference
    let reader_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => match thread.heap_mut().alloc_byte_array(&vec![0u8; count]) {
            Ok(array_ref) => return PreHookResult::Bypass(Some(EmValue::ObjectRef(array_ref))),
            Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
        },
    };

    // Get the underlying stream
    let Some(stream_ref) = get_binary_reader_stream(reader_ref, thread) else {
        match thread.heap_mut().alloc_byte_array(&vec![0u8; count]) {
            Ok(array_ref) => return PreHookResult::Bypass(Some(EmValue::ObjectRef(array_ref))),
            Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
        }
    };

    // Get stream data and position
    let Some((data, position)) = thread.heap().get_stream_data(stream_ref) else {
        match thread.heap_mut().alloc_byte_array(&vec![0u8; count]) {
            Ok(array_ref) => return PreHookResult::Bypass(Some(EmValue::ObjectRef(array_ref))),
            Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
        }
    };

    // Calculate how many bytes we can read
    let available = data.len().saturating_sub(position);
    let to_read = count.min(available);

    // Read the bytes
    let bytes: Vec<u8> = data[position..position + to_read].to_vec();

    // Update stream position
    thread
        .heap_mut()
        .set_stream_position(stream_ref, position + to_read);

    match thread.heap_mut().alloc_byte_array(&bytes) {
        Ok(array_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(array_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.IO.BinaryReader.ReadInt16` method.
///
/// # Handled Overloads
///
/// - `BinaryReader.ReadInt16() -> Int16`
///
/// # Returns
///
/// A 2-byte signed integer read in little-endian format
fn binary_reader_read_int16_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    // Get the BinaryReader object reference
    let reader_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
    };

    // Get the underlying stream
    let Some(stream_ref) = get_binary_reader_stream(reader_ref, thread) else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    // Get stream data and position
    let Some((data, position)) = thread.heap().get_stream_data(stream_ref) else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    // Need 2 bytes
    if position + 2 > data.len() {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    }

    // Read little-endian i16
    let value = i16::from_le_bytes([data[position], data[position + 1]]);

    // Update stream position
    thread
        .heap_mut()
        .set_stream_position(stream_ref, position + 2);

    PreHookResult::Bypass(Some(EmValue::I32(i32::from(value))))
}

/// Hook for `System.IO.BinaryReader.ReadInt32` method.
///
/// # Handled Overloads
///
/// - `BinaryReader.ReadInt32() -> Int32`
///
/// # Returns
///
/// A 4-byte signed integer read in little-endian format
fn binary_reader_read_int32_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    // Get the BinaryReader object reference
    let reader_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
    };

    // Get the underlying stream
    let Some(stream_ref) = get_binary_reader_stream(reader_ref, thread) else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    // Get stream data and position
    let Some((data, position)) = thread.heap().get_stream_data(stream_ref) else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    // Need 4 bytes
    if position + 4 > data.len() {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    }

    // Read little-endian i32
    let value = i32::from_le_bytes([
        data[position],
        data[position + 1],
        data[position + 2],
        data[position + 3],
    ]);

    // Update stream position
    thread
        .heap_mut()
        .set_stream_position(stream_ref, position + 4);

    PreHookResult::Bypass(Some(EmValue::I32(value)))
}

/// Hook for `System.IO.BinaryReader.ReadInt64` method.
///
/// # Handled Overloads
///
/// - `BinaryReader.ReadInt64() -> Int64`
///
/// # Returns
///
/// An 8-byte signed integer read in little-endian format
fn binary_reader_read_int64_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    // Get the BinaryReader object reference
    let reader_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(Some(EmValue::I64(0))),
    };

    // Get the underlying stream
    let Some(stream_ref) = get_binary_reader_stream(reader_ref, thread) else {
        return PreHookResult::Bypass(Some(EmValue::I64(0)));
    };

    // Get stream data and position
    let Some((data, position)) = thread.heap().get_stream_data(stream_ref) else {
        return PreHookResult::Bypass(Some(EmValue::I64(0)));
    };

    // Need 8 bytes
    if position + 8 > data.len() {
        return PreHookResult::Bypass(Some(EmValue::I64(0)));
    }

    // Read little-endian i64
    let value = i64::from_le_bytes([
        data[position],
        data[position + 1],
        data[position + 2],
        data[position + 3],
        data[position + 4],
        data[position + 5],
        data[position + 6],
        data[position + 7],
    ]);

    // Update stream position
    thread
        .heap_mut()
        .set_stream_position(stream_ref, position + 8);

    PreHookResult::Bypass(Some(EmValue::I64(value)))
}

/// Hook for `System.IO.BinaryReader.ReadString` method.
///
/// # Handled Overloads
///
/// - `BinaryReader.ReadString() -> String`
///
/// # Returns
///
/// A string read using 7-bit encoded length prefix followed by UTF-8 bytes
fn binary_reader_read_string_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    // Get the BinaryReader object reference
    let reader_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => match thread.heap_mut().alloc_string("") {
            Ok(str_ref) => return PreHookResult::Bypass(Some(EmValue::ObjectRef(str_ref))),
            Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
        },
    };

    // Get the underlying stream
    let Some(stream_ref) = get_binary_reader_stream(reader_ref, thread) else {
        match thread.heap_mut().alloc_string("") {
            Ok(str_ref) => return PreHookResult::Bypass(Some(EmValue::ObjectRef(str_ref))),
            Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
        }
    };

    // Get stream data and position
    let Some((data, mut position)) = thread.heap().get_stream_data(stream_ref) else {
        match thread.heap_mut().alloc_string("") {
            Ok(str_ref) => return PreHookResult::Bypass(Some(EmValue::ObjectRef(str_ref))),
            Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
        }
    };

    // Read 7-bit encoded length (LEB128-style)
    let mut length: usize = 0;
    let mut shift = 0;
    loop {
        if position >= data.len() {
            match thread.heap_mut().alloc_string("") {
                Ok(str_ref) => return PreHookResult::Bypass(Some(EmValue::ObjectRef(str_ref))),
                Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
            }
        }
        let byte = data[position];
        position += 1;
        length |= ((byte & 0x7F) as usize) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        // Prevent infinite loop on malformed data
        if shift > 35 {
            break;
        }
    }

    // Read the string bytes
    if position + length > data.len() {
        // Not enough data, read what we can
        let available = data.len().saturating_sub(position);
        let str_bytes = &data[position..position + available];
        let s = String::from_utf8_lossy(str_bytes).into_owned();
        position += available;
        thread.heap_mut().set_stream_position(stream_ref, position);
        match thread.heap_mut().alloc_string(&s) {
            Ok(str_ref) => return PreHookResult::Bypass(Some(EmValue::ObjectRef(str_ref))),
            Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
        }
    }

    let str_bytes = &data[position..position + length];
    let s = String::from_utf8_lossy(str_bytes).into_owned();
    position += length;

    // Update stream position
    thread.heap_mut().set_stream_position(stream_ref, position);

    match thread.heap_mut().alloc_string(&s) {
        Ok(str_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(str_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emulation::runtime::hook::HookManager;
    use crate::test::emulation::create_test_thread;

    #[test]
    fn test_register_hooks() {
        let mut manager = HookManager::new();
        register(&mut manager);
        assert_eq!(manager.len(), 22);
    }

    #[test]
    fn test_stream_close_hook() {
        let ctx = HookContext::new(Token::new(0x0A000001), "System.IO", "Stream", "Close");

        let mut thread = create_test_thread();
        let result = stream_close_pre(&ctx, &mut thread);

        match result {
            PreHookResult::Bypass(None) => {}
            _ => panic!("Expected Bypass(None)"),
        }
    }

    #[test]
    fn test_stream_read_byte_eof_without_stream() {
        let ctx = HookContext::new(Token::new(0x0A000001), "System.IO", "Stream", "ReadByte");

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
        let stream_ref = thread.heap_mut().alloc_stream(data).unwrap();

        let this = EmValue::ObjectRef(stream_ref);
        let ctx = HookContext::new(Token::new(0x0A000001), "System.IO", "Stream", "ReadByte")
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
        let stream_ref = thread.heap_mut().alloc_stream(data).unwrap();

        let this = EmValue::ObjectRef(stream_ref);
        let ctx = HookContext::new(Token::new(0x0A000001), "System.IO", "Stream", "get_Length")
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
        let stream_ref = thread.heap_mut().alloc_stream(data).unwrap();

        let this = EmValue::ObjectRef(stream_ref);
        let get_pos_ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "Stream",
            "get_Position",
        )
        .with_this(Some(&this));
        let read_byte_ctx =
            HookContext::new(Token::new(0x0A000002), "System.IO", "Stream", "ReadByte")
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
        let stream_ref = thread.heap_mut().alloc_stream(data).unwrap();

        let this = EmValue::ObjectRef(stream_ref);
        let args = [EmValue::I64(3)];
        let set_pos_ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "Stream",
            "set_Position",
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
        )
        .with_this(Some(&this));
        let result = stream_get_position_pre(&get_pos_ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I64(3)))
        ));

        // Read byte at position 3 (value should be 4)
        let read_byte_ctx =
            HookContext::new(Token::new(0x0A000003), "System.IO", "Stream", "ReadByte")
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
        let stream_ref = thread.heap_mut().alloc_stream(data.clone()).unwrap();

        let this = EmValue::ObjectRef(stream_ref);
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "MemoryStream",
            "ToArray",
        )
        .with_this(Some(&this));

        let result = memory_stream_to_array_pre(&ctx, &mut thread);

        // Verify we get an array back
        let array_ref = match result {
            PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) => r,
            _ => panic!("Expected Bypass with ObjectRef"),
        };

        // Verify array contents
        let retrieved = thread.heap().get_byte_array(array_ref).unwrap();
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
        let ctx = HookContext::new(Token::new(0x0A000001), "System.IO", "MemoryStream", ".ctor")
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
        let stream_ref = thread.heap_mut().alloc_stream(data).unwrap();

        let this = EmValue::ObjectRef(stream_ref);

        // Seek to position 2 from beginning (origin = 0)
        let args = [EmValue::I64(2), EmValue::I32(0)];
        let seek_ctx =
            HookContext::new(Token::new(0x0A000001), "System.IO", "MemoryStream", "Seek")
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
        )
        .with_this(Some(&this));
        let result = stream_read_byte_pre(&read_ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(30)))
        ));

        // Seek to end (origin = 2) with offset -1
        let args = [EmValue::I64(-1), EmValue::I32(2)];
        let seek_ctx =
            HookContext::new(Token::new(0x0A000003), "System.IO", "MemoryStream", "Seek")
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

    /// Helper to create a BinaryReader backed by a stream with the given data.
    fn create_binary_reader(thread: &mut EmulationThread, data: Vec<u8>) -> HeapRef {
        // Create the stream
        let stream_ref = thread.heap_mut().alloc_stream(data).unwrap();

        // Create an empty object for the BinaryReader
        let reader_token = Token::new(0x0200_0001); // Dummy type token
        let reader_ref = thread.heap_mut().alloc_object(reader_token).unwrap();

        // Call constructor to store the stream reference
        let this = EmValue::ObjectRef(reader_ref);
        let args = [EmValue::ObjectRef(stream_ref)];
        let ctx = HookContext::new(Token::new(0x0A000001), "System.IO", "BinaryReader", ".ctor")
            .with_this(Some(&this))
            .with_args(&args);

        binary_reader_ctor_pre(&ctx, thread);

        reader_ref
    }

    #[test]
    fn test_binary_reader_read_byte_from_stream() {
        let mut thread = create_test_thread();
        let reader_ref = create_binary_reader(&mut thread, vec![0x42, 0x55, 0x88]);

        let this = EmValue::ObjectRef(reader_ref);
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "BinaryReader",
            "ReadByte",
        )
        .with_this(Some(&this));

        // Read first byte
        let result = binary_reader_read_byte_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(0x42)))
        ));

        // Read second byte
        let result = binary_reader_read_byte_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(0x55)))
        ));

        // Read third byte
        let result = binary_reader_read_byte_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(0x88)))
        ));
    }

    #[test]
    fn test_binary_reader_read_bytes_from_stream() {
        let mut thread = create_test_thread();
        let reader_ref = create_binary_reader(&mut thread, vec![1, 2, 3, 4, 5, 6, 7, 8]);

        let this = EmValue::ObjectRef(reader_ref);
        let args = [EmValue::I32(5)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "BinaryReader",
            "ReadBytes",
        )
        .with_this(Some(&this))
        .with_args(&args);

        let result = binary_reader_read_bytes_pre(&ctx, &mut thread);

        let array_ref = match result {
            PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) => r,
            _ => panic!("Expected Bypass with ObjectRef"),
        };

        let bytes = thread.heap().get_byte_array(array_ref).unwrap();
        assert_eq!(bytes.as_slice(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_binary_reader_read_int16() {
        let mut thread = create_test_thread();
        // Little-endian: 0x1234 = [0x34, 0x12]
        let reader_ref = create_binary_reader(&mut thread, vec![0x34, 0x12]);

        let this = EmValue::ObjectRef(reader_ref);
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "BinaryReader",
            "ReadInt16",
        )
        .with_this(Some(&this));

        let result = binary_reader_read_int16_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(0x1234)))
        ));
    }

    #[test]
    fn test_binary_reader_read_int32() {
        let mut thread = create_test_thread();
        // Little-endian: 0x12345678 = [0x78, 0x56, 0x34, 0x12]
        let reader_ref = create_binary_reader(&mut thread, vec![0x78, 0x56, 0x34, 0x12]);

        let this = EmValue::ObjectRef(reader_ref);
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "BinaryReader",
            "ReadInt32",
        )
        .with_this(Some(&this));

        let result = binary_reader_read_int32_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(0x12345678)))
        ));
    }

    #[test]
    fn test_binary_reader_read_int64() {
        let mut thread = create_test_thread();
        // Little-endian: 0x0102030405060708
        let reader_ref = create_binary_reader(
            &mut thread,
            vec![0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01],
        );

        let this = EmValue::ObjectRef(reader_ref);
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "BinaryReader",
            "ReadInt64",
        )
        .with_this(Some(&this));

        let result = binary_reader_read_int64_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I64(0x0102030405060708)))
        ));
    }

    #[test]
    fn test_binary_reader_read_string() {
        let mut thread = create_test_thread();
        // Length-prefixed string: length=5, "Hello"
        let reader_ref = create_binary_reader(&mut thread, vec![5, b'H', b'e', b'l', b'l', b'o']);

        let this = EmValue::ObjectRef(reader_ref);
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "BinaryReader",
            "ReadString",
        )
        .with_this(Some(&this));

        let result = binary_reader_read_string_pre(&ctx, &mut thread);

        let str_ref = match result {
            PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) => r,
            _ => panic!("Expected Bypass with ObjectRef"),
        };

        let s = thread.heap().get_string(str_ref).unwrap();
        assert_eq!(s.as_ref(), "Hello");
    }

    #[test]
    fn test_binary_reader_mixed_reads() {
        let mut thread = create_test_thread();
        // Create data with: byte, int32, string
        // byte: 0xFF
        // int32: 0x12345678 (little-endian: [0x78, 0x56, 0x34, 0x12])
        // string: length=4, "Test"
        let reader_ref = create_binary_reader(
            &mut thread,
            vec![
                0xFF, // byte
                0x78, 0x56, 0x34, 0x12, // int32
                4, b'T', b'e', b's', b't', // string
            ],
        );

        let this = EmValue::ObjectRef(reader_ref);

        // Read byte
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "BinaryReader",
            "ReadByte",
        )
        .with_this(Some(&this));
        let result = binary_reader_read_byte_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(0xFF)))
        ));

        // Read int32
        let ctx = HookContext::new(
            Token::new(0x0A000002),
            "System.IO",
            "BinaryReader",
            "ReadInt32",
        )
        .with_this(Some(&this));
        let result = binary_reader_read_int32_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(0x12345678)))
        ));

        // Read string
        let ctx = HookContext::new(
            Token::new(0x0A000003),
            "System.IO",
            "BinaryReader",
            "ReadString",
        )
        .with_this(Some(&this));
        let result = binary_reader_read_string_pre(&ctx, &mut thread);

        let str_ref = match result {
            PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) => r,
            _ => panic!("Expected Bypass with ObjectRef"),
        };
        let s = thread.heap().get_string(str_ref).unwrap();
        assert_eq!(s.as_ref(), "Test");
    }
}
