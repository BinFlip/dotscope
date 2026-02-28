//! `System.IO.Stream`, `MemoryStream`, `BinaryReader`, and `BinaryWriter` method hooks.
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
//! | `Stream.set_Position` | Set position | Updates stream position |
//! | `Stream.Close()` | Close stream | No-op |
//! | `Stream.Dispose()` | Dispose stream | No-op |
//!
//! ## BinaryReader Methods
//!
//! | Method | Description | Implementation |
//! |--------|-------------|----------------|
//! | `BinaryReader..ctor(Stream)` | Create reader | Stores stream reference in synthetic field |
//! | `BinaryReader.get_BaseStream` | Get underlying stream | Returns stored stream reference |
//! | `BinaryReader.Read()` | Read single char | UTF-8 decoded char as int, -1 on EOF |
//! | `BinaryReader.Read(byte[], int, int)` | Read into buffer | Copies bytes into array |
//! | `BinaryReader.ReadBoolean()` | Read boolean | 1 byte, nonzero = true |
//! | `BinaryReader.ReadByte()` | Read byte | 1 byte unsigned |
//! | `BinaryReader.ReadSByte()` | Read signed byte | 1 byte signed |
//! | `BinaryReader.ReadBytes(int)` | Read byte array | Reads from stream, advances position |
//! | `BinaryReader.ReadChar()` | Read character | UTF-8 decoded char |
//! | `BinaryReader.ReadChars(int)` | Read character array | UTF-8 decoded characters |
//! | `BinaryReader.ReadInt16()` | Read 16-bit int | Reads little-endian from stream |
//! | `BinaryReader.ReadUInt16()` | Read unsigned 16-bit | Reads little-endian from stream |
//! | `BinaryReader.ReadInt32()` | Read 32-bit int | Reads little-endian from stream |
//! | `BinaryReader.ReadUInt32()` | Read unsigned 32-bit | Reads little-endian, bit pattern preserved |
//! | `BinaryReader.ReadInt64()` | Read 64-bit int | Reads little-endian from stream |
//! | `BinaryReader.ReadUInt64()` | Read unsigned 64-bit | Reads little-endian, bit pattern preserved |
//! | `BinaryReader.ReadSingle()` | Read float | 4 bytes IEEE 754 |
//! | `BinaryReader.ReadDouble()` | Read double | 8 bytes IEEE 754 |
//! | `BinaryReader.ReadDecimal()` | Read decimal | 16 bytes, approximated as f64 |
//! | `BinaryReader.ReadString()` | Read length-prefixed string | Reads 7-bit length + UTF-8 bytes |
//! | `BinaryReader.Read7BitEncodedInt()` | Read LEB128 int | Variable-length 32-bit integer |
//! | `BinaryReader.PeekChar()` | Peek next char | Returns char without advancing |
//! | `BinaryReader.Close()` | Close reader | No-op |
//! | `BinaryReader.Dispose()` | Dispose reader | No-op |
//!
//! ## BinaryWriter Methods
//!
//! | Method | Description | Implementation |
//! |--------|-------------|----------------|
//! | `BinaryWriter..ctor(Stream)` | Create writer | Stores stream reference in synthetic field |
//! | `BinaryWriter.get_BaseStream` | Get underlying stream | Returns stored stream reference |
//! | `BinaryWriter.Write(bool)` | Write boolean | 1 byte (0 or 1) |
//! | `BinaryWriter.Write(byte)` | Write byte | 1 byte unsigned |
//! | `BinaryWriter.Write(sbyte)` | Write signed byte | 1 byte signed |
//! | `BinaryWriter.Write(char)` | Write character | UTF-8 encoded |
//! | `BinaryWriter.Write(short)` | Write 16-bit int | 2 bytes little-endian |
//! | `BinaryWriter.Write(ushort)` | Write unsigned 16-bit | 2 bytes little-endian |
//! | `BinaryWriter.Write(int)` | Write 32-bit int | 4 bytes little-endian |
//! | `BinaryWriter.Write(uint)` | Write unsigned 32-bit | 4 bytes little-endian |
//! | `BinaryWriter.Write(long)` | Write 64-bit int | 8 bytes little-endian |
//! | `BinaryWriter.Write(ulong)` | Write unsigned 64-bit | 8 bytes little-endian |
//! | `BinaryWriter.Write(float)` | Write single | 4 bytes IEEE 754 |
//! | `BinaryWriter.Write(double)` | Write double | 8 bytes IEEE 754 |
//! | `BinaryWriter.Write(byte[])` | Write byte array | Writes raw bytes to stream |
//! | `BinaryWriter.Write(byte[], int, int)` | Write byte slice | Writes slice to stream |
//! | `BinaryWriter.Write(string)` | Write string | Writes 7-bit length prefix + UTF-8 bytes |
//! | `BinaryWriter.Seek(int, SeekOrigin)` | Seek in stream | Sets position based on origin |
//! | `BinaryWriter.Flush()` | Flush writer | No-op |
//! | `BinaryWriter.Close()` | Close writer | No-op |
//! | `BinaryWriter.Dispose()` | Dispose writer | No-op |
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
//! - **Write support**: `BinaryWriter` and `MemoryStream.Write` operations append data to streams
//!
//! [`HeapObject::Stream`]: crate::emulation::memory::HeapObject::Stream

use crate::{
    emulation::{
        runtime::hook::{Hook, HookContext, HookManager, PreHookResult},
        thread::EmulationThread,
        EmValue, HeapRef,
    },
    metadata::{token::Token, typesystem::CilFlavor},
    utils::{decompress_deflate, decompress_gzip, write_7bit_encoded_int},
};

/// Returns the synthetic field token used to store the underlying stream reference in BinaryReader.
/// Uses a high value to avoid collision with real field tokens.
fn binary_reader_stream_field() -> Token {
    Token::new(0xFFFF_0001)
}

/// Returns the synthetic field token used to store the underlying stream reference in BinaryWriter.
/// Uses a high value to avoid collision with real field tokens.
fn binary_writer_stream_field() -> Token {
    Token::new(0xFFFF_0002)
}

/// Registers all Stream, BinaryReader, and BinaryWriter method hooks with the given hook manager.
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
/// - `Stream.set_Position`, `Stream.Close`, `Stream.Dispose`
///
/// ## BinaryReader
/// - `BinaryReader..ctor(Stream)`, `BinaryReader.get_BaseStream`
/// - `BinaryReader.ReadByte`, `BinaryReader.ReadBytes`
/// - `BinaryReader.ReadInt16`, `BinaryReader.ReadInt32`, `BinaryReader.ReadInt64`
/// - `BinaryReader.ReadString`, `BinaryReader.Close`
///
/// ## BinaryWriter
/// - `BinaryWriter..ctor(Stream)`, `BinaryWriter.get_BaseStream`
/// - `BinaryWriter.Write` (multiple overloads)
/// - `BinaryWriter.Flush`, `BinaryWriter.Close`, `BinaryWriter.Dispose`
pub fn register(manager: &HookManager) {
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
        Hook::new("System.IO.MemoryStream.WriteByte")
            .match_name("System.IO", "MemoryStream", "WriteByte")
            .pre(stream_write_byte_pre),
    );

    manager.register(
        Hook::new("System.IO.MemoryStream.Seek")
            .match_name("System.IO", "MemoryStream", "Seek")
            .pre(stream_seek_pre),
    );

    manager.register(
        Hook::new("System.IO.MemoryStream.GetBuffer")
            .match_name("System.IO", "MemoryStream", "GetBuffer")
            .pre(memory_stream_get_buffer_pre),
    );

    manager.register(
        Hook::new("System.IO.MemoryStream.SetLength")
            .match_name("System.IO", "MemoryStream", "SetLength")
            .pre(stream_set_length_pre),
    );

    manager.register(
        Hook::new("System.IO.MemoryStream.get_Capacity")
            .match_name("System.IO", "MemoryStream", "get_Capacity")
            .pre(stream_get_length_pre),
    );

    manager.register(
        Hook::new("System.IO.MemoryStream.CopyTo")
            .match_name("System.IO", "MemoryStream", "CopyTo")
            .pre(stream_copy_to_pre),
    );

    manager.register(
        Hook::new("System.IO.MemoryStream.Flush")
            .match_name("System.IO", "MemoryStream", "Flush")
            .pre(stream_close_pre),
    );

    manager.register(
        Hook::new("System.IO.MemoryStream.Close")
            .match_name("System.IO", "MemoryStream", "Close")
            .pre(stream_close_pre),
    );

    manager.register(
        Hook::new("System.IO.MemoryStream.Dispose")
            .match_name("System.IO", "MemoryStream", "Dispose")
            .pre(stream_dispose_pre),
    );

    manager.register(
        Hook::new("System.IO.MemoryStream.get_CanRead")
            .match_name("System.IO", "MemoryStream", "get_CanRead")
            .pre(stream_can_true_pre),
    );

    manager.register(
        Hook::new("System.IO.MemoryStream.get_CanSeek")
            .match_name("System.IO", "MemoryStream", "get_CanSeek")
            .pre(stream_can_true_pre),
    );

    manager.register(
        Hook::new("System.IO.MemoryStream.get_CanWrite")
            .match_name("System.IO", "MemoryStream", "get_CanWrite")
            .pre(stream_can_true_pre),
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
        Hook::new("System.IO.Stream.get_Position")
            .match_name("System.IO", "Stream", "get_Position")
            .pre(stream_get_position_pre),
    );

    manager.register(
        Hook::new("System.IO.Stream.set_Position")
            .match_name("System.IO", "Stream", "set_Position")
            .pre(stream_set_position_pre),
    );

    manager.register(
        Hook::new("System.IO.Stream.Write")
            .match_name("System.IO", "Stream", "Write")
            .pre(stream_write_pre),
    );

    manager.register(
        Hook::new("System.IO.Stream.WriteByte")
            .match_name("System.IO", "Stream", "WriteByte")
            .pre(stream_write_byte_pre),
    );

    manager.register(
        Hook::new("System.IO.Stream.Seek")
            .match_name("System.IO", "Stream", "Seek")
            .pre(stream_seek_pre),
    );

    manager.register(
        Hook::new("System.IO.Stream.SetLength")
            .match_name("System.IO", "Stream", "SetLength")
            .pre(stream_set_length_pre),
    );

    manager.register(
        Hook::new("System.IO.Stream.CopyTo")
            .match_name("System.IO", "Stream", "CopyTo")
            .pre(stream_copy_to_pre),
    );

    manager.register(
        Hook::new("System.IO.Stream.Flush")
            .match_name("System.IO", "Stream", "Flush")
            .pre(stream_close_pre),
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

    manager.register(
        Hook::new("System.IO.Stream.get_CanRead")
            .match_name("System.IO", "Stream", "get_CanRead")
            .pre(stream_can_true_pre),
    );

    manager.register(
        Hook::new("System.IO.Stream.get_CanSeek")
            .match_name("System.IO", "Stream", "get_CanSeek")
            .pre(stream_can_true_pre),
    );

    manager.register(
        Hook::new("System.IO.Stream.get_CanWrite")
            .match_name("System.IO", "Stream", "get_CanWrite")
            .pre(stream_can_true_pre),
    );

    // BinaryReader methods
    manager.register(
        Hook::new("System.IO.BinaryReader..ctor")
            .match_name("System.IO", "BinaryReader", ".ctor")
            .pre(binary_reader_ctor_pre),
    );

    manager.register(
        Hook::new("System.IO.BinaryReader.get_BaseStream")
            .match_name("System.IO", "BinaryReader", "get_BaseStream")
            .pre(binary_reader_get_base_stream_pre),
    );

    manager.register(
        Hook::new("System.IO.BinaryReader.Read")
            .match_name("System.IO", "BinaryReader", "Read")
            .pre(binary_reader_read_pre),
    );

    manager.register(
        Hook::new("System.IO.BinaryReader.ReadBoolean")
            .match_name("System.IO", "BinaryReader", "ReadBoolean")
            .pre(binary_reader_read_boolean_pre),
    );

    manager.register(
        Hook::new("System.IO.BinaryReader.ReadByte")
            .match_name("System.IO", "BinaryReader", "ReadByte")
            .pre(binary_reader_read_byte_pre),
    );

    manager.register(
        Hook::new("System.IO.BinaryReader.ReadSByte")
            .match_name("System.IO", "BinaryReader", "ReadSByte")
            .pre(binary_reader_read_sbyte_pre),
    );

    manager.register(
        Hook::new("System.IO.BinaryReader.ReadBytes")
            .match_name("System.IO", "BinaryReader", "ReadBytes")
            .pre(binary_reader_read_bytes_pre),
    );

    manager.register(
        Hook::new("System.IO.BinaryReader.ReadChar")
            .match_name("System.IO", "BinaryReader", "ReadChar")
            .pre(binary_reader_read_char_pre),
    );

    manager.register(
        Hook::new("System.IO.BinaryReader.ReadChars")
            .match_name("System.IO", "BinaryReader", "ReadChars")
            .pre(binary_reader_read_chars_pre),
    );

    manager.register(
        Hook::new("System.IO.BinaryReader.ReadInt16")
            .match_name("System.IO", "BinaryReader", "ReadInt16")
            .pre(binary_reader_read_int16_pre),
    );

    manager.register(
        Hook::new("System.IO.BinaryReader.ReadUInt16")
            .match_name("System.IO", "BinaryReader", "ReadUInt16")
            .pre(binary_reader_read_uint16_pre),
    );

    manager.register(
        Hook::new("System.IO.BinaryReader.ReadInt32")
            .match_name("System.IO", "BinaryReader", "ReadInt32")
            .pre(binary_reader_read_int32_pre),
    );

    manager.register(
        Hook::new("System.IO.BinaryReader.ReadUInt32")
            .match_name("System.IO", "BinaryReader", "ReadUInt32")
            .pre(binary_reader_read_uint32_pre),
    );

    manager.register(
        Hook::new("System.IO.BinaryReader.ReadInt64")
            .match_name("System.IO", "BinaryReader", "ReadInt64")
            .pre(binary_reader_read_int64_pre),
    );

    manager.register(
        Hook::new("System.IO.BinaryReader.ReadUInt64")
            .match_name("System.IO", "BinaryReader", "ReadUInt64")
            .pre(binary_reader_read_uint64_pre),
    );

    manager.register(
        Hook::new("System.IO.BinaryReader.ReadSingle")
            .match_name("System.IO", "BinaryReader", "ReadSingle")
            .pre(binary_reader_read_single_pre),
    );

    manager.register(
        Hook::new("System.IO.BinaryReader.ReadDouble")
            .match_name("System.IO", "BinaryReader", "ReadDouble")
            .pre(binary_reader_read_double_pre),
    );

    manager.register(
        Hook::new("System.IO.BinaryReader.ReadDecimal")
            .match_name("System.IO", "BinaryReader", "ReadDecimal")
            .pre(binary_reader_read_decimal_pre),
    );

    manager.register(
        Hook::new("System.IO.BinaryReader.ReadString")
            .match_name("System.IO", "BinaryReader", "ReadString")
            .pre(binary_reader_read_string_pre),
    );

    manager.register(
        Hook::new("System.IO.BinaryReader.Read7BitEncodedInt")
            .match_name("System.IO", "BinaryReader", "Read7BitEncodedInt")
            .pre(binary_reader_read_7bit_encoded_int_pre),
    );

    manager.register(
        Hook::new("System.IO.BinaryReader.PeekChar")
            .match_name("System.IO", "BinaryReader", "PeekChar")
            .pre(binary_reader_peek_char_pre),
    );

    manager.register(
        Hook::new("System.IO.BinaryReader.Close")
            .match_name("System.IO", "BinaryReader", "Close")
            .pre(stream_close_pre),
    );

    manager.register(
        Hook::new("System.IO.BinaryReader.Dispose")
            .match_name("System.IO", "BinaryReader", "Dispose")
            .pre(stream_dispose_pre),
    );

    // BinaryWriter methods
    manager.register(
        Hook::new("System.IO.BinaryWriter..ctor")
            .match_name("System.IO", "BinaryWriter", ".ctor")
            .pre(binary_writer_ctor_pre),
    );

    manager.register(
        Hook::new("System.IO.BinaryWriter.get_BaseStream")
            .match_name("System.IO", "BinaryWriter", "get_BaseStream")
            .pre(binary_writer_get_base_stream_pre),
    );

    manager.register(
        Hook::new("System.IO.BinaryWriter.Write")
            .match_name("System.IO", "BinaryWriter", "Write")
            .pre(binary_writer_write_pre),
    );

    manager.register(
        Hook::new("System.IO.BinaryWriter.Seek")
            .match_name("System.IO", "BinaryWriter", "Seek")
            .pre(binary_writer_seek_pre),
    );

    manager.register(
        Hook::new("System.IO.BinaryWriter.Flush")
            .match_name("System.IO", "BinaryWriter", "Flush")
            .pre(stream_close_pre),
    );

    manager.register(
        Hook::new("System.IO.BinaryWriter.Close")
            .match_name("System.IO", "BinaryWriter", "Close")
            .pre(stream_close_pre),
    );

    manager.register(
        Hook::new("System.IO.BinaryWriter.Dispose")
            .match_name("System.IO", "BinaryWriter", "Dispose")
            .pre(stream_dispose_pre),
    );

    // DeflateStream methods
    manager.register(
        Hook::new("System.IO.Compression.DeflateStream..ctor")
            .match_name("System.IO.Compression", "DeflateStream", ".ctor")
            .pre(deflate_stream_ctor_pre),
    );

    manager.register(
        Hook::new("System.IO.Compression.DeflateStream.Read")
            .match_name("System.IO.Compression", "DeflateStream", "Read")
            .pre(compressed_stream_read_pre),
    );

    manager.register(
        Hook::new("System.IO.Compression.DeflateStream.Close")
            .match_name("System.IO.Compression", "DeflateStream", "Close")
            .pre(stream_close_pre),
    );

    manager.register(
        Hook::new("System.IO.Compression.DeflateStream.Dispose")
            .match_name("System.IO.Compression", "DeflateStream", "Dispose")
            .pre(stream_dispose_pre),
    );

    // GZipStream methods
    manager.register(
        Hook::new("System.IO.Compression.GZipStream..ctor")
            .match_name("System.IO.Compression", "GZipStream", ".ctor")
            .pre(gzip_stream_ctor_pre),
    );

    manager.register(
        Hook::new("System.IO.Compression.GZipStream.Read")
            .match_name("System.IO.Compression", "GZipStream", "Read")
            .pre(compressed_stream_read_pre),
    );

    manager.register(
        Hook::new("System.IO.Compression.GZipStream.Close")
            .match_name("System.IO.Compression", "GZipStream", "Close")
            .pre(stream_close_pre),
    );

    manager.register(
        Hook::new("System.IO.Compression.GZipStream.Dispose")
            .match_name("System.IO.Compression", "GZipStream", "Dispose")
            .pre(stream_dispose_pre),
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
            .or_else(|| {
                thread
                    .heap()
                    .get_array_as_bytes(*array_ref, ctx.pointer_size)
            })
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
    // Safe: values validated as non-negative
    #[allow(clippy::cast_sign_loss)]
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
    // Safe: values validated as non-negative
    #[allow(clippy::cast_sign_loss)]
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
    // Safe: values validated as non-negative
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
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
    thread
        .heap_mut()
        .set_stream_position(stream_ref, clamped_pos);

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

    thread.heap_mut().write_to_stream(stream_ref, &[byte]);
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

    thread.heap_mut().truncate_stream(stream_ref, new_length);
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

    // Read remaining data from source (from current position to end)
    let Some((data, position)) = thread.heap().get_stream_data(src_ref) else {
        return PreHookResult::Bypass(None);
    };

    if position < data.len() {
        let remaining = &data[position..];
        thread.heap_mut().write_to_stream(dst_ref, remaining);
    }

    // Update source position to end
    let len = data.len();
    thread.heap_mut().set_stream_position(src_ref, len);

    PreHookResult::Bypass(None)
}

/// Hook for `Stream.get_CanRead`, `Stream.get_CanSeek`, `Stream.get_CanWrite` properties.
///
/// Emulated streams always support all operations.
fn stream_can_true_pre(_ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    PreHookResult::Bypass(Some(EmValue::I32(1)))
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

/// Helper function to get the underlying stream reference from a BinaryWriter.
fn get_binary_writer_stream(writer_ref: HeapRef, thread: &EmulationThread) -> Option<HeapRef> {
    let field_value = thread
        .heap()
        .get_field(writer_ref, binary_writer_stream_field())
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

/// Hook for `System.IO.BinaryReader.get_BaseStream` property.
///
/// # Handled Overloads
///
/// - `BinaryReader.BaseStream { get; } -> Stream`
///
/// # Returns
///
/// The underlying stream reference stored during construction
fn binary_reader_get_base_stream_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let reader_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(Some(EmValue::Null)),
    };

    match get_binary_reader_stream(reader_ref, thread) {
        Some(stream_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(stream_ref))),
        None => PreHookResult::Bypass(Some(EmValue::Null)),
    }
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
    // Safe: value validated as non-negative
    #[allow(clippy::cast_sign_loss)]
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

/// Hook for `System.IO.BinaryReader.Read` method.
///
/// # Handled Overloads
///
/// - `BinaryReader.Read() -> Int32` — reads a single character, returns its code point or -1 on EOF
/// - `BinaryReader.Read(Byte[], Int32, Int32) -> Int32` — reads bytes into a buffer
///
/// # Returns
///
/// For the no-arg overload: the character code point, or -1 on EOF.
/// For the buffer overload: the number of bytes actually read.
fn binary_reader_read_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let reader_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
    };

    let Some(stream_ref) = get_binary_reader_stream(reader_ref, thread) else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    // Dispatch based on argument count
    match ctx.args.len() {
        // Read() — single character as int, or -1 on EOF
        0 => {
            let Some((data, position)) = thread.heap().get_stream_data(stream_ref) else {
                return PreHookResult::Bypass(Some(EmValue::I32(-1)));
            };

            if position >= data.len() {
                return PreHookResult::Bypass(Some(EmValue::I32(-1)));
            }

            // Read a single UTF-8 character
            let remaining = &data[position..];
            let s = String::from_utf8_lossy(remaining);
            if let Some(ch) = s.chars().next() {
                let char_len = ch.len_utf8();
                thread
                    .heap_mut()
                    .set_stream_position(stream_ref, position + char_len);
                #[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
                PreHookResult::Bypass(Some(EmValue::I32(ch as i32)))
            } else {
                PreHookResult::Bypass(Some(EmValue::I32(-1)))
            }
        }
        // Read(byte[], int, int) — buffer read
        3 => {
            #[allow(clippy::cast_sign_loss)]
            let (buffer_ref, offset, count) =
                match (ctx.args.first(), ctx.args.get(1), ctx.args.get(2)) {
                    (Some(EmValue::ObjectRef(b)), Some(EmValue::I32(o)), Some(EmValue::I32(c))) => {
                        (*b, *o as usize, *c as usize)
                    }
                    _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
                };

            let Some((data, position)) = thread.heap().get_stream_data(stream_ref) else {
                return PreHookResult::Bypass(Some(EmValue::I32(0)));
            };

            let available = data.len().saturating_sub(position);
            let to_read = count.min(available);

            for i in 0..to_read {
                if let Some(&byte) = data.get(position + i) {
                    let _ = thread.heap_mut().set_array_element(
                        buffer_ref,
                        offset + i,
                        EmValue::I32(i32::from(byte)),
                    );
                }
            }

            thread
                .heap_mut()
                .set_stream_position(stream_ref, position + to_read);

            #[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
            PreHookResult::Bypass(Some(EmValue::I32(to_read as i32)))
        }
        _ => PreHookResult::Bypass(Some(EmValue::I32(0))),
    }
}

/// Hook for `System.IO.BinaryReader.ReadBoolean` method.
///
/// # Handled Overloads
///
/// - `BinaryReader.ReadBoolean() -> Boolean`
///
/// # Returns
///
/// `true` (1) if the byte is nonzero, `false` (0) otherwise
fn binary_reader_read_boolean_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let reader_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
    };

    let Some(stream_ref) = get_binary_reader_stream(reader_ref, thread) else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    let Some((data, position)) = thread.heap().get_stream_data(stream_ref) else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    if position >= data.len() {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    }

    let value = if data[position] != 0 { 1 } else { 0 };

    thread
        .heap_mut()
        .set_stream_position(stream_ref, position + 1);

    PreHookResult::Bypass(Some(EmValue::I32(value)))
}

/// Hook for `System.IO.BinaryReader.ReadSByte` method.
///
/// # Handled Overloads
///
/// - `BinaryReader.ReadSByte() -> SByte`
///
/// # Returns
///
/// A signed byte (-128 to 127) widened to I32
fn binary_reader_read_sbyte_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let reader_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
    };

    let Some(stream_ref) = get_binary_reader_stream(reader_ref, thread) else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    let Some((data, position)) = thread.heap().get_stream_data(stream_ref) else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    if position >= data.len() {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    }

    let value = data[position] as i8;

    thread
        .heap_mut()
        .set_stream_position(stream_ref, position + 1);

    PreHookResult::Bypass(Some(EmValue::I32(i32::from(value))))
}

/// Hook for `System.IO.BinaryReader.ReadChar` method.
///
/// # Handled Overloads
///
/// - `BinaryReader.ReadChar() -> Char`
///
/// # Returns
///
/// A single UTF-8 decoded character widened to I32
fn binary_reader_read_char_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let reader_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
    };

    let Some(stream_ref) = get_binary_reader_stream(reader_ref, thread) else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    let Some((data, position)) = thread.heap().get_stream_data(stream_ref) else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    if position >= data.len() {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    }

    // Decode one UTF-8 character from the stream
    let remaining = &data[position..];
    let s = String::from_utf8_lossy(remaining);
    if let Some(ch) = s.chars().next() {
        let char_len = ch.len_utf8();
        thread
            .heap_mut()
            .set_stream_position(stream_ref, position + char_len);
        #[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
        PreHookResult::Bypass(Some(EmValue::I32(ch as i32)))
    } else {
        PreHookResult::Bypass(Some(EmValue::I32(0)))
    }
}

/// Hook for `System.IO.BinaryReader.ReadChars` method.
///
/// # Handled Overloads
///
/// - `BinaryReader.ReadChars(Int32) -> Char[]`
///
/// # Parameters
///
/// - `count`: Number of characters to read
///
/// # Returns
///
/// An array of characters
fn binary_reader_read_chars_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    #[allow(clippy::cast_sign_loss)]
    let count = match ctx.args.first() {
        Some(EmValue::I32(v)) => *v as usize,
        _ => 0,
    };

    let reader_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => {
            return alloc_char_array_result(thread, &[]);
        }
    };

    let Some(stream_ref) = get_binary_reader_stream(reader_ref, thread) else {
        return alloc_char_array_result(thread, &[]);
    };

    let Some((data, mut position)) = thread.heap().get_stream_data(stream_ref) else {
        return alloc_char_array_result(thread, &[]);
    };

    // Decode `count` UTF-8 characters
    let mut chars = Vec::with_capacity(count);
    for _ in 0..count {
        if position >= data.len() {
            break;
        }
        let remaining = &data[position..];
        let s = String::from_utf8_lossy(remaining);
        if let Some(ch) = s.chars().next() {
            chars.push(ch);
            position += ch.len_utf8();
        } else {
            break;
        }
    }

    thread.heap_mut().set_stream_position(stream_ref, position);

    alloc_char_array_result(thread, &chars)
}

/// Allocates a Char[] array on the heap and returns it as a `PreHookResult`.
fn alloc_char_array_result(thread: &mut EmulationThread, chars: &[char]) -> PreHookResult {
    let elements: Vec<EmValue> = chars
        .iter()
        .map(|&c| {
            #[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
            EmValue::I32(c as i32)
        })
        .collect();
    match thread
        .heap_mut()
        .alloc_array_with_values(CilFlavor::Char, elements)
    {
        Ok(arr_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.IO.BinaryReader.ReadUInt16` method.
///
/// # Handled Overloads
///
/// - `BinaryReader.ReadUInt16() -> UInt16`
///
/// # Returns
///
/// A 2-byte unsigned integer read in little-endian format, widened to I32
fn binary_reader_read_uint16_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let reader_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
    };

    let Some(stream_ref) = get_binary_reader_stream(reader_ref, thread) else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    let Some((data, position)) = thread.heap().get_stream_data(stream_ref) else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    if position + 2 > data.len() {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    }

    let value = u16::from_le_bytes([data[position], data[position + 1]]);

    thread
        .heap_mut()
        .set_stream_position(stream_ref, position + 2);

    PreHookResult::Bypass(Some(EmValue::I32(i32::from(value))))
}

/// Hook for `System.IO.BinaryReader.ReadUInt32` method.
///
/// # Handled Overloads
///
/// - `BinaryReader.ReadUInt32() -> UInt32`
///
/// # Returns
///
/// A 4-byte unsigned integer read in little-endian format, stored as I32
/// (bit pattern preserved, as per CLI spec where uint32 maps to I32 on the stack)
fn binary_reader_read_uint32_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let reader_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
    };

    let Some(stream_ref) = get_binary_reader_stream(reader_ref, thread) else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    let Some((data, position)) = thread.heap().get_stream_data(stream_ref) else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    if position + 4 > data.len() {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    }

    // Read as u32 and reinterpret as i32 (bit pattern preserved per CLI spec)
    let value = u32::from_le_bytes([
        data[position],
        data[position + 1],
        data[position + 2],
        data[position + 3],
    ]);

    thread
        .heap_mut()
        .set_stream_position(stream_ref, position + 4);

    #[allow(clippy::cast_possible_wrap)]
    PreHookResult::Bypass(Some(EmValue::I32(value as i32)))
}

/// Hook for `System.IO.BinaryReader.ReadUInt64` method.
///
/// # Handled Overloads
///
/// - `BinaryReader.ReadUInt64() -> UInt64`
///
/// # Returns
///
/// An 8-byte unsigned integer read in little-endian format, stored as I64
/// (bit pattern preserved, as per CLI spec where uint64 maps to I64 on the stack)
fn binary_reader_read_uint64_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let reader_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(Some(EmValue::I64(0))),
    };

    let Some(stream_ref) = get_binary_reader_stream(reader_ref, thread) else {
        return PreHookResult::Bypass(Some(EmValue::I64(0)));
    };

    let Some((data, position)) = thread.heap().get_stream_data(stream_ref) else {
        return PreHookResult::Bypass(Some(EmValue::I64(0)));
    };

    if position + 8 > data.len() {
        return PreHookResult::Bypass(Some(EmValue::I64(0)));
    }

    let value = u64::from_le_bytes([
        data[position],
        data[position + 1],
        data[position + 2],
        data[position + 3],
        data[position + 4],
        data[position + 5],
        data[position + 6],
        data[position + 7],
    ]);

    thread
        .heap_mut()
        .set_stream_position(stream_ref, position + 8);

    #[allow(clippy::cast_possible_wrap)]
    PreHookResult::Bypass(Some(EmValue::I64(value as i64)))
}

/// Hook for `System.IO.BinaryReader.ReadSingle` method.
///
/// # Handled Overloads
///
/// - `BinaryReader.ReadSingle() -> Single`
///
/// # Returns
///
/// A 4-byte IEEE 754 single-precision floating point value
fn binary_reader_read_single_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let reader_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(Some(EmValue::F32(0.0))),
    };

    let Some(stream_ref) = get_binary_reader_stream(reader_ref, thread) else {
        return PreHookResult::Bypass(Some(EmValue::F32(0.0)));
    };

    let Some((data, position)) = thread.heap().get_stream_data(stream_ref) else {
        return PreHookResult::Bypass(Some(EmValue::F32(0.0)));
    };

    if position + 4 > data.len() {
        return PreHookResult::Bypass(Some(EmValue::F32(0.0)));
    }

    let value = f32::from_le_bytes([
        data[position],
        data[position + 1],
        data[position + 2],
        data[position + 3],
    ]);

    thread
        .heap_mut()
        .set_stream_position(stream_ref, position + 4);

    PreHookResult::Bypass(Some(EmValue::F32(value)))
}

/// Hook for `System.IO.BinaryReader.ReadDouble` method.
///
/// # Handled Overloads
///
/// - `BinaryReader.ReadDouble() -> Double`
///
/// # Returns
///
/// An 8-byte IEEE 754 double-precision floating point value
fn binary_reader_read_double_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let reader_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(Some(EmValue::F64(0.0))),
    };

    let Some(stream_ref) = get_binary_reader_stream(reader_ref, thread) else {
        return PreHookResult::Bypass(Some(EmValue::F64(0.0)));
    };

    let Some((data, position)) = thread.heap().get_stream_data(stream_ref) else {
        return PreHookResult::Bypass(Some(EmValue::F64(0.0)));
    };

    if position + 8 > data.len() {
        return PreHookResult::Bypass(Some(EmValue::F64(0.0)));
    }

    let value = f64::from_le_bytes([
        data[position],
        data[position + 1],
        data[position + 2],
        data[position + 3],
        data[position + 4],
        data[position + 5],
        data[position + 6],
        data[position + 7],
    ]);

    thread
        .heap_mut()
        .set_stream_position(stream_ref, position + 8);

    PreHookResult::Bypass(Some(EmValue::F64(value)))
}

/// Hook for `System.IO.BinaryReader.ReadDecimal` method.
///
/// # Handled Overloads
///
/// - `BinaryReader.ReadDecimal() -> Decimal`
///
/// # Returns
///
/// A 16-byte Decimal value. Since the emulator does not have a native Decimal type,
/// we read the 16 bytes and reconstruct it as an f64 approximation using the .NET
/// Decimal binary format: bytes 0-3 = lo, 4-7 = mid, 8-11 = hi, 12-15 = flags.
fn binary_reader_read_decimal_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let reader_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(Some(EmValue::F64(0.0))),
    };

    let Some(stream_ref) = get_binary_reader_stream(reader_ref, thread) else {
        return PreHookResult::Bypass(Some(EmValue::F64(0.0)));
    };

    let Some((data, position)) = thread.heap().get_stream_data(stream_ref) else {
        return PreHookResult::Bypass(Some(EmValue::F64(0.0)));
    };

    if position + 16 > data.len() {
        return PreHookResult::Bypass(Some(EmValue::F64(0.0)));
    }

    // .NET Decimal binary layout (BinaryReader order):
    // bytes 0-3:   lo (Int32)
    // bytes 4-7:   mid (Int32)
    // bytes 8-11:  hi (Int32)
    // bytes 12-15: flags (sign in bit 31, scale in bits 16-23)
    let lo = u32::from_le_bytes([
        data[position],
        data[position + 1],
        data[position + 2],
        data[position + 3],
    ]);
    let mid = u32::from_le_bytes([
        data[position + 4],
        data[position + 5],
        data[position + 6],
        data[position + 7],
    ]);
    let hi = u32::from_le_bytes([
        data[position + 8],
        data[position + 9],
        data[position + 10],
        data[position + 11],
    ]);
    let flags = u32::from_le_bytes([
        data[position + 12],
        data[position + 13],
        data[position + 14],
        data[position + 15],
    ]);

    let negative = (flags & 0x8000_0000) != 0;
    let scale = (flags >> 16) & 0xFF;

    // Reconstruct the 96-bit integer mantissa as f64
    let mantissa = f64::from(lo)
        + f64::from(mid) * 4_294_967_296.0
        + f64::from(hi) * 18_446_744_073_709_551_616.0;
    let divisor = 10_f64.powi(scale as i32);
    let value = if negative {
        -mantissa / divisor
    } else {
        mantissa / divisor
    };

    thread
        .heap_mut()
        .set_stream_position(stream_ref, position + 16);

    PreHookResult::Bypass(Some(EmValue::F64(value)))
}

/// Hook for `System.IO.BinaryReader.Read7BitEncodedInt` method.
///
/// # Handled Overloads
///
/// - `BinaryReader.Read7BitEncodedInt() -> Int32`
///
/// # Returns
///
/// A 32-bit integer decoded from 7-bit encoded (LEB128-style) format
fn binary_reader_read_7bit_encoded_int_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let reader_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
    };

    let Some(stream_ref) = get_binary_reader_stream(reader_ref, thread) else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    let Some((data, mut position)) = thread.heap().get_stream_data(stream_ref) else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    let mut result: u32 = 0;
    let mut shift = 0;
    loop {
        if position >= data.len() || shift > 35 {
            break;
        }
        let byte = data[position];
        position += 1;
        result |= u32::from(byte & 0x7F) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }

    thread.heap_mut().set_stream_position(stream_ref, position);

    #[allow(clippy::cast_possible_wrap)]
    PreHookResult::Bypass(Some(EmValue::I32(result as i32)))
}

/// Hook for `System.IO.BinaryReader.PeekChar` method.
///
/// # Handled Overloads
///
/// - `BinaryReader.PeekChar() -> Int32`
///
/// # Returns
///
/// The next character without advancing the stream, or -1 on EOF
fn binary_reader_peek_char_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let reader_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(Some(EmValue::I32(-1))),
    };

    let Some(stream_ref) = get_binary_reader_stream(reader_ref, thread) else {
        return PreHookResult::Bypass(Some(EmValue::I32(-1)));
    };

    let Some((data, position)) = thread.heap().get_stream_data(stream_ref) else {
        return PreHookResult::Bypass(Some(EmValue::I32(-1)));
    };

    if position >= data.len() {
        return PreHookResult::Bypass(Some(EmValue::I32(-1)));
    }

    // Decode one UTF-8 character without advancing position
    let remaining = &data[position..];
    let s = String::from_utf8_lossy(remaining);
    if let Some(ch) = s.chars().next() {
        #[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
        PreHookResult::Bypass(Some(EmValue::I32(ch as i32)))
    } else {
        PreHookResult::Bypass(Some(EmValue::I32(-1)))
    }
}

/// Hook for `System.IO.BinaryWriter..ctor` constructor.
///
/// # Handled Overloads
///
/// - `BinaryWriter..ctor(Stream)`
/// - `BinaryWriter..ctor(Stream, Encoding)` (encoding argument is ignored)
///
/// # Parameters
///
/// - `output`: The underlying stream to write to
fn binary_writer_ctor_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    // Get the BinaryWriter object reference
    let writer_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(None),
    };

    // Get the stream argument
    let stream_ref = match ctx.args.first() {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(None),
    };

    // Store the stream reference in the BinaryWriter's field
    let _ = thread.heap_mut().set_field(
        writer_ref,
        binary_writer_stream_field(),
        EmValue::ObjectRef(stream_ref),
    );

    PreHookResult::Bypass(None)
}

/// Hook for `System.IO.BinaryWriter.get_BaseStream` property.
///
/// # Handled Overloads
///
/// - `BinaryWriter.BaseStream { get; } -> Stream`
///
/// # Returns
///
/// The underlying stream reference stored during construction
fn binary_writer_get_base_stream_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let writer_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(Some(EmValue::Null)),
    };

    match get_binary_writer_stream(writer_ref, thread) {
        Some(stream_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(stream_ref))),
        None => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.IO.BinaryWriter.Write` method.
///
/// # Handled Overloads
///
/// - `BinaryWriter.Write(Boolean)` - Writes 1 byte (0 or 1)
/// - `BinaryWriter.Write(Byte)` - Writes 1 byte
/// - `BinaryWriter.Write(SByte)` - Writes 1 byte (signed)
/// - `BinaryWriter.Write(Int16)` - Writes 2 bytes little-endian
/// - `BinaryWriter.Write(UInt16)` - Writes 2 bytes little-endian
/// - `BinaryWriter.Write(Char)` - Writes UTF-8 encoded character
/// - `BinaryWriter.Write(Int32)` - Writes 4 bytes little-endian
/// - `BinaryWriter.Write(UInt32)` - Writes 4 bytes little-endian
/// - `BinaryWriter.Write(Int64)` - Writes 8 bytes little-endian
/// - `BinaryWriter.Write(UInt64)` - Writes 8 bytes little-endian
/// - `BinaryWriter.Write(Single)` - Writes 4 bytes IEEE 754
/// - `BinaryWriter.Write(Double)` - Writes 8 bytes IEEE 754
/// - `BinaryWriter.Write(Byte[])` - Writes raw bytes
/// - `BinaryWriter.Write(Byte[], Int32, Int32)` - Writes a slice of bytes
/// - `BinaryWriter.Write(String)` - Writes a 7-bit length prefix followed by UTF-8 bytes
///
/// # Implementation Note
///
/// Uses `param_types` from the hook context to correctly distinguish between overloads
/// that share the same `EmValue` representation (e.g. `Write(byte)` vs `Write(int)` both
/// arrive as `I32`). Falls back to type/count-based heuristics when `param_types` is unavailable.
fn binary_writer_write_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let writer_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(None),
    };

    let Some(stream_ref) = get_binary_writer_stream(writer_ref, thread) else {
        return PreHookResult::Bypass(None);
    };

    // Try to use param_types for precise overload dispatch
    if let Some(param_types) = ctx.param_types {
        if param_types.len() == 1 {
            match param_types[0] {
                // Write(Boolean) — 1 byte: 0 or 1
                CilFlavor::Boolean => {
                    let v = match ctx.args.first() {
                        Some(EmValue::I32(v)) => {
                            if *v != 0 {
                                1u8
                            } else {
                                0u8
                            }
                        }
                        _ => 0u8,
                    };
                    thread.heap_mut().write_to_stream(stream_ref, &[v]);
                    return PreHookResult::Bypass(None);
                }
                // Write(Byte) — 1 byte unsigned
                CilFlavor::U1 => {
                    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
                    let v = match ctx.args.first() {
                        Some(EmValue::I32(v)) => *v as u8,
                        _ => 0u8,
                    };
                    thread.heap_mut().write_to_stream(stream_ref, &[v]);
                    return PreHookResult::Bypass(None);
                }
                // Write(SByte) — 1 byte signed
                CilFlavor::I1 => {
                    #[allow(clippy::cast_possible_truncation)]
                    let v = match ctx.args.first() {
                        Some(EmValue::I32(v)) => *v as i8 as u8,
                        _ => 0u8,
                    };
                    thread.heap_mut().write_to_stream(stream_ref, &[v]);
                    return PreHookResult::Bypass(None);
                }
                // Write(Char) — UTF-8 encoded character
                CilFlavor::Char => {
                    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
                    if let Some(EmValue::I32(v)) = ctx.args.first() {
                        if let Some(ch) = char::from_u32(*v as u32) {
                            let mut buf = [0u8; 4];
                            let encoded = ch.encode_utf8(&mut buf);
                            thread
                                .heap_mut()
                                .write_to_stream(stream_ref, encoded.as_bytes());
                        }
                    }
                    return PreHookResult::Bypass(None);
                }
                // Write(Int16) — 2 bytes little-endian
                CilFlavor::I2 => {
                    #[allow(clippy::cast_possible_truncation)]
                    let v = match ctx.args.first() {
                        Some(EmValue::I32(v)) => *v as i16,
                        _ => 0i16,
                    };
                    thread
                        .heap_mut()
                        .write_to_stream(stream_ref, &v.to_le_bytes());
                    return PreHookResult::Bypass(None);
                }
                // Write(UInt16) — 2 bytes little-endian
                CilFlavor::U2 => {
                    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
                    let v = match ctx.args.first() {
                        Some(EmValue::I32(v)) => *v as u16,
                        _ => 0u16,
                    };
                    thread
                        .heap_mut()
                        .write_to_stream(stream_ref, &v.to_le_bytes());
                    return PreHookResult::Bypass(None);
                }
                // Write(Int32) — 4 bytes little-endian
                CilFlavor::I4 => {
                    let v = match ctx.args.first() {
                        Some(EmValue::I32(v)) => *v,
                        _ => 0i32,
                    };
                    thread
                        .heap_mut()
                        .write_to_stream(stream_ref, &v.to_le_bytes());
                    return PreHookResult::Bypass(None);
                }
                // Write(UInt32) — 4 bytes little-endian
                CilFlavor::U4 => {
                    #[allow(clippy::cast_sign_loss)]
                    let v = match ctx.args.first() {
                        Some(EmValue::I32(v)) => *v as u32,
                        _ => 0u32,
                    };
                    thread
                        .heap_mut()
                        .write_to_stream(stream_ref, &v.to_le_bytes());
                    return PreHookResult::Bypass(None);
                }
                // Write(Int64) — 8 bytes little-endian
                CilFlavor::I8 => {
                    let v = match ctx.args.first() {
                        Some(EmValue::I64(v)) => *v,
                        Some(EmValue::I32(v)) => i64::from(*v),
                        _ => 0i64,
                    };
                    thread
                        .heap_mut()
                        .write_to_stream(stream_ref, &v.to_le_bytes());
                    return PreHookResult::Bypass(None);
                }
                // Write(UInt64) — 8 bytes little-endian
                CilFlavor::U8 => {
                    #[allow(clippy::cast_sign_loss)]
                    let v = match ctx.args.first() {
                        Some(EmValue::I64(v)) => *v as u64,
                        Some(EmValue::I32(v)) => *v as u64,
                        _ => 0u64,
                    };
                    thread
                        .heap_mut()
                        .write_to_stream(stream_ref, &v.to_le_bytes());
                    return PreHookResult::Bypass(None);
                }
                // Write(Single) — 4 bytes IEEE 754
                CilFlavor::R4 => {
                    let v = match ctx.args.first() {
                        Some(EmValue::F32(v)) => *v,
                        Some(EmValue::F64(v)) => *v as f32,
                        _ => 0.0f32,
                    };
                    thread
                        .heap_mut()
                        .write_to_stream(stream_ref, &v.to_le_bytes());
                    return PreHookResult::Bypass(None);
                }
                // Write(Double) — 8 bytes IEEE 754
                CilFlavor::R8 => {
                    let v = match ctx.args.first() {
                        Some(EmValue::F64(v)) => *v,
                        Some(EmValue::F32(v)) => f64::from(*v),
                        _ => 0.0f64,
                    };
                    thread
                        .heap_mut()
                        .write_to_stream(stream_ref, &v.to_le_bytes());
                    return PreHookResult::Bypass(None);
                }
                // Write(String) — 7-bit length prefix + UTF-8
                CilFlavor::String => {
                    if let Some(EmValue::ObjectRef(obj_ref)) = ctx.args.first() {
                        if let Ok(s) = thread.heap().get_string(*obj_ref) {
                            let s_bytes = s.as_bytes().to_vec();
                            let mut len_prefix = Vec::new();
                            #[allow(clippy::cast_possible_truncation)]
                            write_7bit_encoded_int(s_bytes.len() as u32, &mut len_prefix);
                            thread.heap_mut().write_to_stream(stream_ref, &len_prefix);
                            thread.heap_mut().write_to_stream(stream_ref, &s_bytes);
                        }
                    }
                    return PreHookResult::Bypass(None);
                }
                _ => {} // Fall through to heuristic dispatch
            }
        }
    }

    // Fallback: heuristic dispatch based on argument types and count
    match (ctx.args.first(), ctx.args.len()) {
        // Write(byte[]) or Write(string) — single ObjectRef argument
        (Some(EmValue::ObjectRef(obj_ref)), 1) => {
            if let Ok(s) = thread.heap().get_string(*obj_ref) {
                // Write(string): 7-bit length prefix + UTF-8 bytes
                let s_bytes = s.as_bytes().to_vec();
                let mut len_prefix = Vec::new();
                #[allow(clippy::cast_possible_truncation)]
                write_7bit_encoded_int(s_bytes.len() as u32, &mut len_prefix);
                thread.heap_mut().write_to_stream(stream_ref, &len_prefix);
                thread.heap_mut().write_to_stream(stream_ref, &s_bytes);
            } else if let Some(bytes) = thread.heap().get_byte_array(*obj_ref) {
                // Write(byte[]): write raw bytes
                thread.heap_mut().write_to_stream(stream_ref, &bytes);
            }
        }
        // Write(byte[], int, int) — write slice of bytes
        (Some(EmValue::ObjectRef(arr_ref)), 3) => {
            #[allow(clippy::cast_sign_loss)]
            if let (Some(EmValue::I32(offset)), Some(EmValue::I32(count))) =
                (ctx.args.get(1), ctx.args.get(2))
            {
                let offset = *offset as usize;
                let count = *count as usize;
                if let Some(bytes) = thread.heap().get_byte_array(*arr_ref) {
                    let end = (offset + count).min(bytes.len());
                    if offset < bytes.len() {
                        thread
                            .heap_mut()
                            .write_to_stream(stream_ref, &bytes[offset..end]);
                    }
                }
            }
        }
        // Write(int) — 4 bytes little-endian (fallback: assumes Int32 when no type info)
        (Some(EmValue::I32(v)), 1) => {
            thread
                .heap_mut()
                .write_to_stream(stream_ref, &v.to_le_bytes());
        }
        // Write(long) — 8 bytes little-endian
        (Some(EmValue::I64(v)), 1) => {
            thread
                .heap_mut()
                .write_to_stream(stream_ref, &v.to_le_bytes());
        }
        // Write(float) — 4 bytes IEEE 754
        (Some(EmValue::F32(v)), 1) => {
            thread
                .heap_mut()
                .write_to_stream(stream_ref, &v.to_le_bytes());
        }
        // Write(double) — 8 bytes IEEE 754
        (Some(EmValue::F64(v)), 1) => {
            thread
                .heap_mut()
                .write_to_stream(stream_ref, &v.to_le_bytes());
        }
        _ => {}
    }

    PreHookResult::Bypass(None)
}

/// Hook for `System.IO.BinaryWriter.Seek` method.
///
/// # Handled Overloads
///
/// - `BinaryWriter.Seek(Int32, SeekOrigin) -> Int64`
///
/// # Parameters
///
/// - `offset`: Byte offset relative to origin
/// - `origin`: Reference point (Begin=0, Current=1, End=2)
fn binary_writer_seek_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let writer_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(Some(EmValue::I64(0))),
    };

    let Some(stream_ref) = get_binary_writer_stream(writer_ref, thread) else {
        return PreHookResult::Bypass(Some(EmValue::I64(0)));
    };

    // Reuse the stream seek logic by building a temporary context for the stream
    let offset = match ctx.args.first() {
        Some(EmValue::I32(v)) => i64::from(*v),
        Some(EmValue::I64(v)) => *v,
        _ => 0,
    };

    let origin = match ctx.args.get(1) {
        Some(EmValue::I32(v)) => *v,
        _ => 0,
    };

    let (length, current_pos) = match thread.heap().get_stream_data(stream_ref) {
        Some((data, pos)) => (data.len(), pos),
        None => return PreHookResult::Bypass(Some(EmValue::I64(0))),
    };

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let new_pos = match origin {
        1 => {
            #[allow(clippy::cast_possible_wrap)]
            let pos = current_pos as i64 + offset;
            pos.max(0) as usize
        }
        2 => {
            #[allow(clippy::cast_possible_wrap)]
            let pos = length as i64 + offset;
            pos.max(0) as usize
        }
        _ => offset.max(0) as usize,
    };

    let clamped_pos = new_pos.min(length);
    thread
        .heap_mut()
        .set_stream_position(stream_ref, clamped_pos);

    #[allow(clippy::cast_possible_wrap)]
    PreHookResult::Bypass(Some(EmValue::I64(clamped_pos as i64)))
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

    thread.heap().replace_with_compressed_stream(
        stream_ref,
        underlying_stream,
        compression_type,
        mode,
    );

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
    if !thread.heap().has_compressed_stream_data(stream_ref) {
        let Some((underlying, compression_type, _mode)) =
            thread.heap().get_compressed_stream_info(stream_ref)
        else {
            return PreHookResult::Bypass(Some(EmValue::I32(0)));
        };

        let Some((compressed_data, _)) = thread.heap().get_stream_data(underlying) else {
            return PreHookResult::Bypass(Some(EmValue::I32(0)));
        };

        let decompressed = match compression_type {
            0 => decompress_deflate(&compressed_data).ok(),
            1 => decompress_gzip(&compressed_data).ok(),
            _ => None,
        };

        let data = decompressed.unwrap_or_default();
        thread.heap().set_compressed_stream_data(stream_ref, data);
    }

    // Read from the decompressed cache
    let Some(bytes) = thread.heap().read_compressed_stream(stream_ref, count) else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    // Copy bytes into the output buffer
    for (i, &byte) in bytes.iter().enumerate() {
        let _ = thread.heap_mut().set_array_element(
            buffer_ref,
            offset + i,
            EmValue::I32(i32::from(byte)),
        );
    }

    #[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
    PreHookResult::Bypass(Some(EmValue::I32(bytes.len() as i32)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        emulation::runtime::hook::HookManager, metadata::typesystem::PointerSize,
        test::emulation::create_test_thread,
    };

    #[test]
    fn test_register_hooks() {
        let manager = HookManager::new();
        register(&manager);
        assert_eq!(manager.len(), 74);
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
        let stream_ref = thread.heap_mut().alloc_stream(data).unwrap();

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
        let stream_ref = thread.heap_mut().alloc_stream(data).unwrap();

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
        let stream_ref = thread.heap_mut().alloc_stream(data).unwrap();

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
        let stream_ref = thread.heap_mut().alloc_stream(data).unwrap();

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
        let stream_ref = thread.heap_mut().alloc_stream(data.clone()).unwrap();

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
        let stream_ref = thread.heap_mut().alloc_stream(data).unwrap();

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
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "BinaryReader",
            ".ctor",
            PointerSize::Bit64,
        )
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
            PointerSize::Bit64,
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
            PointerSize::Bit64,
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
            PointerSize::Bit64,
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
            PointerSize::Bit64,
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
            PointerSize::Bit64,
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
            PointerSize::Bit64,
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
            PointerSize::Bit64,
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
            PointerSize::Bit64,
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
            PointerSize::Bit64,
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
