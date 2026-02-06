//! `System.Text.Encoding` method hooks.
//!
//! This module provides hook implementations for text encoding and decoding
//! methods commonly used in obfuscation for string concealment and data
//! transformation.
//!
//! # Overview
//!
//! Text encoding is fundamental to .NET string handling and is heavily used by
//! obfuscators to encrypt and decrypt strings at runtime. These hooks support
//! multiple encodings and automatically capture decoded strings for analysis.
//!
//! # Emulated .NET Methods
//!
//! ## Encoding Properties
//!
//! | Method | Description |
//! |--------|-------------|
//! | `Encoding.get_UTF8` | Returns UTF-8 encoding instance |
//! | `Encoding.get_ASCII` | Returns ASCII encoding instance |
//! | `Encoding.get_Unicode` | Returns UTF-16 LE encoding instance |
//! | `Encoding.get_BigEndianUnicode` | Returns UTF-16 BE encoding instance |
//! | `Encoding.get_UTF32` | Returns UTF-32 encoding instance |
//! | `Encoding.GetEncoding(int)` | Returns encoding by code page |
//!
//! ## Encoding Base Methods
//!
//! | Method | Description |
//! |--------|-------------|
//! | `Encoding.GetBytes(string)` | Encodes string to byte array |
//! | `Encoding.GetString(byte[])` | Decodes byte array to string |
//! | `Encoding.GetByteCount(string)` | Returns encoded byte count |
//! | `Encoding.GetCharCount(byte[])` | Returns decoded character count |
//!
//! ## Specific Encoding Classes
//!
//! | Class | GetBytes | GetString |
//! |-------|----------|-----------|
//! | `UTF8Encoding` | UTF-8 encode | UTF-8 decode |
//! | `ASCIIEncoding` | ASCII encode | ASCII decode |
//! | `UnicodeEncoding` | UTF-16 LE encode | UTF-16 LE decode |
//!
//! # Deobfuscation Use Cases
//!
//! ## String Decryption
//!
//! Obfuscators encrypt strings and decode them at runtime:
//!
//! ```csharp
//! byte[] encrypted = GetResource("strings");
//! byte[] decrypted = DecryptAes(encrypted, key);
//! string secret = Encoding.UTF8.GetString(decrypted);
//! ```
//!
//! ## Base64 + Encoding
//!
//! Common pattern combining Base64 with encoding:
//!
//! ```csharp
//! byte[] bytes = Convert.FromBase64String(obfuscated);
//! string plaintext = Encoding.UTF8.GetString(bytes);
//! ```
//!
//! ## Unicode Obfuscation
//!
//! Some obfuscators use UTF-16 or other encodings:
//!
//! ```csharp
//! byte[] data = ...; // Embedded resource
//! string decoded = Encoding.Unicode.GetString(data);
//! ```
//!
//! # String Capture
//!
//! All `GetString` methods automatically capture decoded strings through
//! the [`CaptureContext`] for analysis:
//!
//! ```ignore
//! // When Encoding.UTF8.GetString(bytes) is called:
//! // 1. Decode bytes to string
//! // 2. Capture string with source location info
//! // 3. Return string reference
//! thread.capture().capture_string(decoded_string, source);
//! ```
//!
//! This enables extraction of decrypted strings from obfuscated code.
//!
//! # Supported Code Pages
//!
//! The `GetEncoding(int)` method supports these code pages:
//!
//! | Code Page | Encoding |
//! |-----------|----------|
//! | 65001 | UTF-8 (default) |
//! | 20127 | US-ASCII |
//! | 1200 | UTF-16 LE |
//! | 1201 | UTF-16 BE |
//! | 12000 | UTF-32 LE |
//!
//! [`CaptureContext`]: crate::emulation::capture::CaptureContext

use crate::emulation::{
    capture::CaptureSource,
    memory::EncodingType,
    runtime::hook::{Hook, HookContext, HookManager, PreHookResult},
    thread::EmulationThread,
    EmValue,
};
use crate::metadata::token::Token;

/// Registers all `System.Text.Encoding` method hooks with the given hook manager.
///
/// # Arguments
///
/// * `manager` - The [`HookManager`] to register hooks with
///
/// # Registered Hooks
///
/// - **Encoding base**: `GetBytes`, `GetString`, `GetByteCount`, `GetCharCount`
/// - **Encoding properties**: `get_UTF8`, `get_ASCII`, `get_Unicode`, `get_BigEndianUnicode`, `get_UTF32`
/// - **Factory**: `GetEncoding(int)`
/// - **UTF8Encoding**: `GetBytes`, `GetString`
/// - **ASCIIEncoding**: `GetBytes`, `GetString`
/// - **UnicodeEncoding**: `GetBytes`, `GetString`
///
/// # String Capture
///
/// All `GetString` methods automatically capture decoded strings through
/// the emulation thread's capture context.
pub fn register(manager: &mut HookManager) {
    // Encoding base methods
    manager.register(
        Hook::new("System.Text.Encoding.GetBytes")
            .match_name("System.Text", "Encoding", "GetBytes")
            .pre(encoding_get_bytes_pre),
    );

    manager.register(
        Hook::new("System.Text.Encoding.GetString")
            .match_name("System.Text", "Encoding", "GetString")
            .pre(encoding_get_string_pre),
    );

    manager.register(
        Hook::new("System.Text.Encoding.GetByteCount")
            .match_name("System.Text", "Encoding", "GetByteCount")
            .pre(encoding_get_byte_count_pre),
    );

    manager.register(
        Hook::new("System.Text.Encoding.GetCharCount")
            .match_name("System.Text", "Encoding", "GetCharCount")
            .pre(encoding_get_char_count_pre),
    );

    // Encoding properties
    manager.register(
        Hook::new("System.Text.Encoding.get_UTF8")
            .match_name("System.Text", "Encoding", "get_UTF8")
            .pre(encoding_get_utf8_pre),
    );

    manager.register(
        Hook::new("System.Text.Encoding.get_ASCII")
            .match_name("System.Text", "Encoding", "get_ASCII")
            .pre(encoding_get_ascii_pre),
    );

    manager.register(
        Hook::new("System.Text.Encoding.get_Unicode")
            .match_name("System.Text", "Encoding", "get_Unicode")
            .pre(encoding_get_unicode_pre),
    );

    manager.register(
        Hook::new("System.Text.Encoding.get_BigEndianUnicode")
            .match_name("System.Text", "Encoding", "get_BigEndianUnicode")
            .pre(encoding_get_big_endian_unicode_pre),
    );

    manager.register(
        Hook::new("System.Text.Encoding.get_UTF32")
            .match_name("System.Text", "Encoding", "get_UTF32")
            .pre(encoding_get_utf32_pre),
    );

    manager.register(
        Hook::new("System.Text.Encoding.GetEncoding")
            .match_name("System.Text", "Encoding", "GetEncoding")
            .pre(encoding_get_encoding_pre),
    );

    // UTF8Encoding methods
    manager.register(
        Hook::new("System.Text.UTF8Encoding.GetBytes")
            .match_name("System.Text", "UTF8Encoding", "GetBytes")
            .pre(utf8_get_bytes_pre),
    );

    manager.register(
        Hook::new("System.Text.UTF8Encoding.GetString")
            .match_name("System.Text", "UTF8Encoding", "GetString")
            .pre(utf8_get_string_pre),
    );

    // ASCIIEncoding methods
    manager.register(
        Hook::new("System.Text.ASCIIEncoding.GetBytes")
            .match_name("System.Text", "ASCIIEncoding", "GetBytes")
            .pre(ascii_get_bytes_pre),
    );

    manager.register(
        Hook::new("System.Text.ASCIIEncoding.GetString")
            .match_name("System.Text", "ASCIIEncoding", "GetString")
            .pre(ascii_get_string_pre),
    );

    // UnicodeEncoding methods
    manager.register(
        Hook::new("System.Text.UnicodeEncoding.GetBytes")
            .match_name("System.Text", "UnicodeEncoding", "GetBytes")
            .pre(unicode_get_bytes_pre),
    );

    manager.register(
        Hook::new("System.Text.UnicodeEncoding.GetString")
            .match_name("System.Text", "UnicodeEncoding", "GetString")
            .pre(unicode_get_string_pre),
    );
}

/// Hook for `System.Text.Encoding.GetBytes` method.
///
/// # Handled Overloads
///
/// - `Encoding.GetBytes(String) -> Byte[]`
/// - `Encoding.GetBytes(Char[]) -> Byte[]`
/// - `Encoding.GetBytes(Char[], Int32, Int32) -> Byte[]`
///
/// # Parameters
///
/// - `s`: String to encode, or
/// - `chars`: Character array to encode
/// - `index`: Starting position in character array
/// - `count`: Number of characters to encode
///
/// # Returns
///
/// A byte array containing the encoded characters
fn encoding_get_bytes_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::Null));
    }

    // Default to UTF-8 encoding
    if let EmValue::ObjectRef(handle) = &ctx.args[0] {
        if let Ok(s) = thread.heap().get_string(*handle) {
            let bytes: Vec<u8> = s.as_bytes().to_vec();
            match thread.heap_mut().alloc_byte_array(&bytes) {
                Ok(arr_handle) => {
                    return PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_handle)))
                }
                Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `System.Text.Encoding.GetString` method.
///
/// # Handled Overloads
///
/// - `Encoding.GetString(Byte[]) -> String`
/// - `Encoding.GetString(Byte[], Int32, Int32) -> String`
///
/// # Parameters
///
/// - `bytes`: Byte array to decode
/// - `index`: Starting position in byte array
/// - `count`: Number of bytes to decode
///
/// # Returns
///
/// A string containing the decoded bytes
///
/// # Note
///
/// Automatically captures the decoded string for deobfuscation analysis.
fn encoding_get_string_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::Null));
    }

    // Default to UTF-8 decoding
    // Handle both GetString(byte[]) and GetString(byte[], int, int) overloads
    if let EmValue::ObjectRef(handle) = &ctx.args[0] {
        if let Some(all_bytes) = thread.heap().get_byte_array(*handle) {
            // Check for GetString(byte[], int offset, int count) overload
            let bytes = if ctx.args.len() >= 3 {
                let offset = match &ctx.args[1] {
                    EmValue::I32(o) => *o as usize,
                    _ => 0,
                };
                let count = match &ctx.args[2] {
                    EmValue::I32(c) => *c as usize,
                    _ => all_bytes.len(),
                };
                if offset + count <= all_bytes.len() {
                    all_bytes[offset..offset + count].to_vec()
                } else {
                    all_bytes
                }
            } else {
                all_bytes
            };

            let s = String::from_utf8_lossy(&bytes).into_owned();

            // Capture decoded string for analysis
            let source = CaptureSource::new(
                thread.current_method().unwrap_or(Token::new(0)),
                thread.id(),
                thread.current_offset().unwrap_or(0),
                0,
            );
            thread.capture().capture_string(s.clone(), source);

            match thread.heap_mut().alloc_string(&s) {
                Ok(str_handle) => {
                    return PreHookResult::Bypass(Some(EmValue::ObjectRef(str_handle)))
                }
                Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `System.Text.Encoding.GetByteCount` method.
///
/// # Handled Overloads
///
/// - `Encoding.GetByteCount(String) -> Int32`
/// - `Encoding.GetByteCount(Char[]) -> Int32`
/// - `Encoding.GetByteCount(Char[], Int32, Int32) -> Int32`
///
/// # Parameters
///
/// - `s`: String to measure, or
/// - `chars`: Character array to measure
/// - `index`: Starting position in character array
/// - `count`: Number of characters to measure
///
/// # Returns
///
/// The number of bytes that would result from encoding
fn encoding_get_byte_count_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    }

    if let EmValue::ObjectRef(handle) = &ctx.args[0] {
        if let Ok(s) = thread.heap().get_string(*handle) {
            // Safe: string lengths don't exceed i32::MAX in practice
            let len = i32::try_from(s.len()).unwrap_or(i32::MAX);
            return PreHookResult::Bypass(Some(EmValue::I32(len)));
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `System.Text.Encoding.GetCharCount` method.
///
/// # Handled Overloads
///
/// - `Encoding.GetCharCount(Byte[]) -> Int32`
/// - `Encoding.GetCharCount(Byte[], Int32, Int32) -> Int32`
///
/// # Parameters
///
/// - `bytes`: Byte array to measure
/// - `index`: Starting position in byte array
/// - `count`: Number of bytes to measure
///
/// # Returns
///
/// The number of characters that would result from decoding
fn encoding_get_char_count_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    }

    if let EmValue::ObjectRef(handle) = &ctx.args[0] {
        if let Some(bytes) = thread.heap().get_byte_array(*handle) {
            // For UTF-8, count UTF-8 characters
            let s = String::from_utf8_lossy(&bytes);
            // Safe: character counts don't exceed i32::MAX in practice
            let count = i32::try_from(s.chars().count()).unwrap_or(i32::MAX);
            return PreHookResult::Bypass(Some(EmValue::I32(count)));
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `System.Text.Encoding.get_UTF8` static property.
///
/// # Handled Overloads
///
/// - `Encoding.UTF8 { get; } -> Encoding`
///
/// # Returns
///
/// A UTF-8 encoding object
fn encoding_get_utf8_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    match thread.heap_mut().alloc_encoding(EncodingType::Utf8) {
        Ok(handle) => PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.Text.Encoding.get_ASCII` static property.
///
/// # Handled Overloads
///
/// - `Encoding.ASCII { get; } -> Encoding`
///
/// # Returns
///
/// An ASCII encoding object
fn encoding_get_ascii_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    match thread.heap_mut().alloc_encoding(EncodingType::Ascii) {
        Ok(handle) => PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.Text.Encoding.get_Unicode` static property.
///
/// # Handled Overloads
///
/// - `Encoding.Unicode { get; } -> Encoding`
///
/// # Returns
///
/// A UTF-16 Little Endian encoding object
fn encoding_get_unicode_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    match thread.heap_mut().alloc_encoding(EncodingType::Utf16Le) {
        Ok(handle) => PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.Text.Encoding.get_BigEndianUnicode` static property.
///
/// # Handled Overloads
///
/// - `Encoding.BigEndianUnicode { get; } -> Encoding`
///
/// # Returns
///
/// A UTF-16 Big Endian encoding object
fn encoding_get_big_endian_unicode_pre(
    _ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    match thread.heap_mut().alloc_encoding(EncodingType::Utf16Be) {
        Ok(handle) => PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.Text.Encoding.get_UTF32` static property.
///
/// # Handled Overloads
///
/// - `Encoding.UTF32 { get; } -> Encoding`
///
/// # Returns
///
/// A UTF-32 encoding object
fn encoding_get_utf32_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    match thread.heap_mut().alloc_encoding(EncodingType::Utf32) {
        Ok(handle) => PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.Text.Encoding.GetEncoding` static method.
///
/// # Handled Overloads
///
/// - `Encoding.GetEncoding(Int32) -> Encoding`
/// - `Encoding.GetEncoding(String) -> Encoding`
///
/// # Parameters
///
/// - `codepage`: Code page identifier, or
/// - `name`: Encoding name
///
/// # Supported Code Pages
///
/// - `65001` - UTF-8 (default for unknown code pages)
/// - `20127` - US-ASCII
/// - `1200` - UTF-16 LE
/// - `1201` - UTF-16 BE
/// - `12000` - UTF-32 LE
///
/// # Returns
///
/// An encoding object for the specified code page
fn encoding_get_encoding_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let encoding_type = if let Some(EmValue::I32(code_page)) = ctx.args.first() {
        match *code_page {
            20127 => EncodingType::Ascii,  // US-ASCII
            1200 => EncodingType::Utf16Le, // UTF-16 LE
            1201 => EncodingType::Utf16Be, // UTF-16 BE
            12000 => EncodingType::Utf32,  // UTF-32 LE
            // 65001 is UTF-8, and unknown code pages default to UTF-8
            _ => EncodingType::Utf8,
        }
    } else {
        EncodingType::Utf8
    };

    match thread.heap_mut().alloc_encoding(encoding_type) {
        Ok(handle) => PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.Text.UTF8Encoding.GetBytes` method.
///
/// # Handled Overloads
///
/// - `UTF8Encoding.GetBytes(String) -> Byte[]`
/// - `UTF8Encoding.GetBytes(Char[]) -> Byte[]`
/// - `UTF8Encoding.GetBytes(Char[], Int32, Int32) -> Byte[]`
///
/// # Parameters
///
/// - `s`: String to encode
///
/// # Returns
///
/// A byte array containing the UTF-8 encoded string
fn utf8_get_bytes_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::Null));
    }

    if let EmValue::ObjectRef(handle) = &ctx.args[0] {
        if let Ok(s) = thread.heap().get_string(*handle) {
            let bytes: Vec<u8> = s.as_bytes().to_vec();
            match thread.heap_mut().alloc_byte_array(&bytes) {
                Ok(arr_handle) => {
                    return PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_handle)))
                }
                Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `System.Text.UTF8Encoding.GetString` method.
///
/// # Handled Overloads
///
/// - `UTF8Encoding.GetString(Byte[]) -> String`
/// - `UTF8Encoding.GetString(Byte[], Int32, Int32) -> String`
///
/// # Parameters
///
/// - `bytes`: Byte array to decode
///
/// # Returns
///
/// A string containing the decoded UTF-8 bytes
///
/// # Note
///
/// Automatically captures the decoded string for deobfuscation analysis.
fn utf8_get_string_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::Null));
    }

    // Handle both GetString(byte[]) and GetString(byte[], int, int) overloads
    if let EmValue::ObjectRef(handle) = &ctx.args[0] {
        if let Some(all_bytes) = thread.heap().get_byte_array(*handle) {
            let bytes = if ctx.args.len() >= 3 {
                let offset = match &ctx.args[1] {
                    EmValue::I32(o) => *o as usize,
                    _ => 0,
                };
                let count = match &ctx.args[2] {
                    EmValue::I32(c) => *c as usize,
                    _ => all_bytes.len(),
                };
                if offset + count <= all_bytes.len() {
                    all_bytes[offset..offset + count].to_vec()
                } else {
                    all_bytes
                }
            } else {
                all_bytes
            };

            let s = String::from_utf8_lossy(&bytes).into_owned();

            // Capture decoded string for analysis
            let source = CaptureSource::new(
                thread.current_method().unwrap_or(Token::new(0)),
                thread.id(),
                thread.current_offset().unwrap_or(0),
                0,
            );
            thread.capture().capture_string(s.clone(), source);

            match thread.heap_mut().alloc_string(&s) {
                Ok(str_handle) => {
                    return PreHookResult::Bypass(Some(EmValue::ObjectRef(str_handle)))
                }
                Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `System.Text.ASCIIEncoding.GetBytes` method.
///
/// # Handled Overloads
///
/// - `ASCIIEncoding.GetBytes(String) -> Byte[]`
/// - `ASCIIEncoding.GetBytes(Char[]) -> Byte[]`
/// - `ASCIIEncoding.GetBytes(Char[], Int32, Int32) -> Byte[]`
///
/// # Parameters
///
/// - `s`: String to encode
///
/// # Returns
///
/// A byte array containing the ASCII encoded string.
/// Non-ASCII characters are replaced with `?` (0x3F).
fn ascii_get_bytes_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::Null));
    }

    if let EmValue::ObjectRef(handle) = &ctx.args[0] {
        if let Ok(s) = thread.heap().get_string(*handle) {
            // ASCII encoding - replace non-ASCII with '?'
            let bytes: Vec<u8> = s
                .chars()
                .map(|c| if c.is_ascii() { c as u8 } else { b'?' })
                .collect();
            match thread.heap_mut().alloc_byte_array(&bytes) {
                Ok(arr_handle) => {
                    return PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_handle)))
                }
                Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `System.Text.ASCIIEncoding.GetString` method.
///
/// # Handled Overloads
///
/// - `ASCIIEncoding.GetString(Byte[]) -> String`
/// - `ASCIIEncoding.GetString(Byte[], Int32, Int32) -> String`
///
/// # Parameters
///
/// - `bytes`: Byte array to decode
///
/// # Returns
///
/// A string containing the decoded ASCII bytes.
/// Bytes >= 128 are replaced with `?`.
///
/// # Note
///
/// Automatically captures the decoded string for deobfuscation analysis.
fn ascii_get_string_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::Null));
    }

    // Handle both GetString(byte[]) and GetString(byte[], int, int) overloads
    if let EmValue::ObjectRef(handle) = &ctx.args[0] {
        if let Some(all_bytes) = thread.heap().get_byte_array(*handle) {
            let bytes = if ctx.args.len() >= 3 {
                let offset = match &ctx.args[1] {
                    EmValue::I32(o) => *o as usize,
                    _ => 0,
                };
                let count = match &ctx.args[2] {
                    EmValue::I32(c) => *c as usize,
                    _ => all_bytes.len(),
                };
                if offset + count <= all_bytes.len() {
                    all_bytes[offset..offset + count].to_vec()
                } else {
                    all_bytes
                }
            } else {
                all_bytes
            };

            // ASCII decoding - only keep valid ASCII
            let s: String = bytes
                .iter()
                .map(|&b| if b < 128 { char::from(b) } else { '?' })
                .collect();

            // Capture decoded string for analysis
            let source = CaptureSource::new(
                thread.current_method().unwrap_or(Token::new(0)),
                thread.id(),
                thread.current_offset().unwrap_or(0),
                0,
            );
            thread.capture().capture_string(s.clone(), source);

            match thread.heap_mut().alloc_string(&s) {
                Ok(str_handle) => {
                    return PreHookResult::Bypass(Some(EmValue::ObjectRef(str_handle)))
                }
                Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `System.Text.UnicodeEncoding.GetBytes` method.
///
/// # Handled Overloads
///
/// - `UnicodeEncoding.GetBytes(String) -> Byte[]`
/// - `UnicodeEncoding.GetBytes(Char[]) -> Byte[]`
/// - `UnicodeEncoding.GetBytes(Char[], Int32, Int32) -> Byte[]`
///
/// # Parameters
///
/// - `s`: String to encode
///
/// # Returns
///
/// A byte array containing the UTF-16 Little Endian encoded string
fn unicode_get_bytes_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::Null));
    }

    if let EmValue::ObjectRef(handle) = &ctx.args[0] {
        if let Ok(s) = thread.heap().get_string(*handle) {
            // UTF-16 LE encoding
            let bytes: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
            match thread.heap_mut().alloc_byte_array(&bytes) {
                Ok(arr_handle) => {
                    return PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_handle)))
                }
                Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `System.Text.UnicodeEncoding.GetString` method.
///
/// # Handled Overloads
///
/// - `UnicodeEncoding.GetString(Byte[]) -> String`
/// - `UnicodeEncoding.GetString(Byte[], Int32, Int32) -> String`
///
/// # Parameters
///
/// - `bytes`: Byte array to decode (must have even length)
///
/// # Returns
///
/// A string containing the decoded UTF-16 Little Endian bytes
///
/// # Note
///
/// Automatically captures the decoded string for deobfuscation analysis.
fn unicode_get_string_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::Null));
    }

    // Handle both GetString(byte[]) and GetString(byte[], int, int) overloads
    if let EmValue::ObjectRef(handle) = &ctx.args[0] {
        if let Some(all_bytes) = thread.heap().get_byte_array(*handle) {
            let bytes = if ctx.args.len() >= 3 {
                let offset = match &ctx.args[1] {
                    EmValue::I32(o) => *o as usize,
                    _ => 0,
                };
                let count = match &ctx.args[2] {
                    EmValue::I32(c) => *c as usize,
                    _ => all_bytes.len(),
                };
                if offset + count <= all_bytes.len() {
                    all_bytes[offset..offset + count].to_vec()
                } else {
                    all_bytes
                }
            } else {
                all_bytes
            };

            // UTF-16 LE decoding
            if bytes.len() % 2 != 0 {
                return PreHookResult::Bypass(Some(EmValue::Null));
            }

            let u16s: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect();

            let s = String::from_utf16_lossy(&u16s);

            // Capture decoded string for analysis
            let source = CaptureSource::new(
                thread.current_method().unwrap_or(Token::new(0)),
                thread.id(),
                thread.current_offset().unwrap_or(0),
                0,
            );
            thread.capture().capture_string(s.clone(), source);

            match thread.heap_mut().alloc_string(&s) {
                Ok(str_handle) => {
                    return PreHookResult::Bypass(Some(EmValue::ObjectRef(str_handle)))
                }
                Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
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
        assert_eq!(manager.len(), 16);
    }

    #[test]
    fn test_utf8_get_bytes_hook() {
        let mut thread = create_test_thread();
        let s = thread.heap_mut().alloc_string("Hello").unwrap();

        let args = [EmValue::ObjectRef(s)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Text",
            "UTF8Encoding",
            "GetBytes",
        )
        .with_args(&args);

        let result = utf8_get_bytes_pre(&ctx, &mut thread);

        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))) = result {
            assert_eq!(
                thread.heap().get_byte_array(handle),
                Some(b"Hello".to_vec())
            );
        } else {
            panic!("Expected Bypass with ObjectRef");
        }
    }

    #[test]
    fn test_utf8_get_string_hook() {
        let mut thread = create_test_thread();
        let data = thread.heap_mut().alloc_byte_array(b"World").unwrap();

        let args = [EmValue::ObjectRef(data)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Text",
            "UTF8Encoding",
            "GetString",
        )
        .with_args(&args);

        let result = utf8_get_string_pre(&ctx, &mut thread);

        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))) = result {
            assert_eq!(&*thread.heap().get_string(handle).unwrap(), "World");
        } else {
            panic!("Expected Bypass with ObjectRef");
        }
    }

    #[test]
    fn test_ascii_get_bytes_hook() {
        let mut thread = create_test_thread();
        let s = thread.heap_mut().alloc_string("Hello").unwrap();

        let args = [EmValue::ObjectRef(s)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Text",
            "ASCIIEncoding",
            "GetBytes",
        )
        .with_args(&args);

        let result = ascii_get_bytes_pre(&ctx, &mut thread);

        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))) = result {
            assert_eq!(
                thread.heap().get_byte_array(handle),
                Some(b"Hello".to_vec())
            );
        } else {
            panic!("Expected Bypass with ObjectRef");
        }
    }

    #[test]
    fn test_unicode_get_bytes_hook() {
        let mut thread = create_test_thread();
        let s = thread.heap_mut().alloc_string("AB").unwrap();

        let args = [EmValue::ObjectRef(s)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Text",
            "UnicodeEncoding",
            "GetBytes",
        )
        .with_args(&args);

        let result = unicode_get_bytes_pre(&ctx, &mut thread);

        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))) = result {
            // "AB" in UTF-16 LE: 0x41 0x00 0x42 0x00
            assert_eq!(
                thread.heap().get_byte_array(handle),
                Some(vec![0x41, 0x00, 0x42, 0x00])
            );
        } else {
            panic!("Expected Bypass with ObjectRef");
        }
    }

    #[test]
    fn test_unicode_get_string_hook() {
        let mut thread = create_test_thread();
        // "AB" in UTF-16 LE
        let data = thread
            .heap_mut()
            .alloc_byte_array(&[0x41, 0x00, 0x42, 0x00])
            .unwrap();

        let args = [EmValue::ObjectRef(data)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Text",
            "UnicodeEncoding",
            "GetString",
        )
        .with_args(&args);

        let result = unicode_get_string_pre(&ctx, &mut thread);

        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))) = result {
            assert_eq!(&*thread.heap().get_string(handle).unwrap(), "AB");
        } else {
            panic!("Expected Bypass with ObjectRef");
        }
    }

    #[test]
    fn test_get_encoding_hook() {
        let mut thread = create_test_thread();

        // Test UTF-8 (default)
        let args = [EmValue::I32(65001)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Text",
            "Encoding",
            "GetEncoding",
        )
        .with_args(&args);
        let result = encoding_get_encoding_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::ObjectRef(_)))
        ));

        // Test ASCII
        let args = [EmValue::I32(20127)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Text",
            "Encoding",
            "GetEncoding",
        )
        .with_args(&args);
        let result = encoding_get_encoding_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::ObjectRef(_)))
        ));
    }
}
