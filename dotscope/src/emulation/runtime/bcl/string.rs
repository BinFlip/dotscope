//! `System.String` method hooks.
//!
//! This module provides hook implementations for string manipulation methods commonly
//! used by obfuscators for string construction, transformation, and comparison.

use crate::emulation::{
    memory::HeapObject,
    runtime::hook::{Hook, HookContext, HookManager, PreHookResult},
    thread::EmulationThread,
    EmValue,
};
use crate::metadata::typesystem::CilFlavor;

/// Registers all `System.String` method hooks.
pub fn register(manager: &mut HookManager) {
    // Static methods
    manager.register(
        Hook::new("System.String.Concat")
            .match_name("System", "String", "Concat")
            .pre(string_concat_pre),
    );
    manager.register(
        Hook::new("System.String.IsNullOrEmpty")
            .match_name("System", "String", "IsNullOrEmpty")
            .pre(string_is_null_or_empty_pre),
    );
    manager.register(
        Hook::new("System.String.Join")
            .match_name("System", "String", "Join")
            .pre(string_join_pre),
    );
    manager.register(
        Hook::new("System.String.Format")
            .match_name("System", "String", "Format")
            .pre(string_format_pre),
    );
    manager.register(
        Hook::new("System.String.Intern")
            .match_name("System", "String", "Intern")
            .pre(string_intern_pre),
    );
    manager.register(
        Hook::new("System.String.IsInterned")
            .match_name("System", "String", "IsInterned")
            .pre(string_is_interned_pre),
    );

    // Instance properties
    manager.register(
        Hook::new("System.String.get_Length")
            .match_name("System", "String", "get_Length")
            .pre(string_get_length_pre),
    );
    manager.register(
        Hook::new("System.String.get_Chars")
            .match_name("System", "String", "get_Chars")
            .pre(string_get_chars_pre),
    );

    // Instance methods
    manager.register(
        Hook::new("System.String.Substring")
            .match_name("System", "String", "Substring")
            .pre(string_substring_pre),
    );
    manager.register(
        Hook::new("System.String.ToCharArray")
            .match_name("System", "String", "ToCharArray")
            .pre(string_to_char_array_pre),
    );
    manager.register(
        Hook::new("System.String.ToUpper")
            .match_name("System", "String", "ToUpper")
            .pre(string_to_upper_pre),
    );
    manager.register(
        Hook::new("System.String.ToLower")
            .match_name("System", "String", "ToLower")
            .pre(string_to_lower_pre),
    );
    manager.register(
        Hook::new("System.String.Trim")
            .match_name("System", "String", "Trim")
            .pre(string_trim_pre),
    );
    manager.register(
        Hook::new("System.String.Replace")
            .match_name("System", "String", "Replace")
            .pre(string_replace_pre),
    );
    manager.register(
        Hook::new("System.String.Split")
            .match_name("System", "String", "Split")
            .pre(string_split_pre),
    );
    manager.register(
        Hook::new("System.String.Contains")
            .match_name("System", "String", "Contains")
            .pre(string_contains_pre),
    );
    manager.register(
        Hook::new("System.String.StartsWith")
            .match_name("System", "String", "StartsWith")
            .pre(string_starts_with_pre),
    );
    manager.register(
        Hook::new("System.String.EndsWith")
            .match_name("System", "String", "EndsWith")
            .pre(string_ends_with_pre),
    );
    manager.register(
        Hook::new("System.String.IndexOf")
            .match_name("System", "String", "IndexOf")
            .pre(string_index_of_pre),
    );
    manager.register(
        Hook::new("System.String.PadLeft")
            .match_name("System", "String", "PadLeft")
            .pre(string_pad_left_pre),
    );
    manager.register(
        Hook::new("System.String.PadRight")
            .match_name("System", "String", "PadRight")
            .pre(string_pad_right_pre),
    );
}

/// Hook for `System.String.Concat` method.
///
/// # Handled Overloads
///
/// - `String.Concat(Object) -> String`
/// - `String.Concat(Object, Object) -> String`
/// - `String.Concat(Object, Object, Object) -> String`
/// - `String.Concat(Object[]) -> String`
/// - `String.Concat(String, String) -> String`
/// - `String.Concat(String, String, String) -> String`
/// - `String.Concat(String, String, String, String) -> String`
/// - `String.Concat(String[]) -> String`
///
/// # Parameters
///
/// - `args`: Variable number of objects or strings to concatenate
///
/// # Returns
///
/// A new string containing the concatenated values
fn string_concat_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let mut result = String::new();

    for arg in ctx.args {
        match arg {
            EmValue::ObjectRef(href) => {
                if let Ok(s) = thread.heap().get_string(*href) {
                    result.push_str(&s);
                }
            }
            EmValue::Null => {}
            EmValue::I32(v) => result.push_str(&v.to_string()),
            EmValue::I64(v) => result.push_str(&v.to_string()),
            EmValue::Bool(v) => result.push_str(if *v { "True" } else { "False" }),
            EmValue::Char(c) => result.push(*c),
            _ => result.push_str("[object]"),
        }
    }

    match thread.heap_mut().alloc_string(&result) {
        Ok(href) => PreHookResult::Bypass(Some(EmValue::ObjectRef(href))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.String.get_Length` property.
///
/// # Handled Overloads
///
/// - `String.Length { get; } -> Int32`
///
/// # Returns
///
/// The number of characters in the string
fn string_get_length_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let Some(EmValue::ObjectRef(href)) = ctx.this else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    match thread.heap().get_string(*href) {
        Ok(s) => {
            let len = i32::try_from(s.chars().count()).unwrap_or(i32::MAX);
            PreHookResult::Bypass(Some(EmValue::I32(len)))
        }
        Err(_) => PreHookResult::Bypass(Some(EmValue::I32(0))),
    }
}

/// Hook for `System.String.get_Chars` indexer property.
///
/// # Handled Overloads
///
/// - `String.Chars[Int32] { get; } -> Char`
/// - `String.this[Int32] { get; } -> Char`
///
/// # Parameters
///
/// - `index`: Zero-based position of the character
///
/// # Returns
///
/// The character at the specified index
fn string_get_chars_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let Some(EmValue::ObjectRef(href)) = ctx.this else {
        return PreHookResult::Bypass(Some(EmValue::Char('\0')));
    };

    let index = ctx
        .args
        .first()
        .map(usize::try_from)
        .and_then(Result::ok)
        .unwrap_or(0);

    match thread.heap().get_string(*href) {
        Ok(s) => match s.chars().nth(index) {
            Some(c) => PreHookResult::Bypass(Some(EmValue::Char(c))),
            None => PreHookResult::Bypass(Some(EmValue::Char('\0'))),
        },
        Err(_) => PreHookResult::Bypass(Some(EmValue::Char('\0'))),
    }
}

/// Hook for `System.String.Substring` method.
///
/// # Handled Overloads
///
/// - `String.Substring(Int32) -> String`
/// - `String.Substring(Int32, Int32) -> String`
///
/// # Parameters
///
/// - `startIndex`: Zero-based starting position
/// - `length`: Optional number of characters to extract
///
/// # Returns
///
/// A substring starting at the specified position
fn string_substring_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let Some(EmValue::ObjectRef(href)) = ctx.this else {
        return PreHookResult::Bypass(Some(EmValue::Null));
    };

    let s = match thread.heap().get_string(*href) {
        Ok(s) => s.to_string(),
        Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
    };

    let start = ctx
        .args
        .first()
        .map(usize::try_from)
        .and_then(Result::ok)
        .unwrap_or(0);

    let substring: String = if ctx.args.len() > 1 {
        let length = usize::try_from(&ctx.args[1]).unwrap_or(0);
        s.chars().skip(start).take(length).collect()
    } else {
        s.chars().skip(start).collect()
    };

    match thread.heap_mut().alloc_string(&substring) {
        Ok(href) => PreHookResult::Bypass(Some(EmValue::ObjectRef(href))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.String.ToCharArray` method.
///
/// # Handled Overloads
///
/// - `String.ToCharArray() -> Char[]`
/// - `String.ToCharArray(Int32, Int32) -> Char[]`
///
/// # Parameters
///
/// - `startIndex`: Optional starting position (default 0)
/// - `length`: Optional number of characters (default all)
///
/// # Returns
///
/// A character array containing the string characters
fn string_to_char_array_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let Some(EmValue::ObjectRef(href)) = ctx.this else {
        return PreHookResult::Bypass(Some(EmValue::Null));
    };

    let s = match thread.heap().get_string(*href) {
        Ok(s) => s.to_string(),
        Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
    };

    let chars: Vec<EmValue> = s.chars().map(EmValue::Char).collect();

    match thread
        .heap_mut()
        .alloc_array_with_values(CilFlavor::Char, chars)
    {
        Ok(href) => PreHookResult::Bypass(Some(EmValue::ObjectRef(href))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.String.ToUpper` method.
///
/// # Handled Overloads
///
/// - `String.ToUpper() -> String`
/// - `String.ToUpper(CultureInfo) -> String`
///
/// # Returns
///
/// A copy of the string converted to uppercase
fn string_to_upper_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let Some(EmValue::ObjectRef(href)) = ctx.this else {
        return PreHookResult::Bypass(Some(EmValue::Null));
    };

    match thread.heap().get_string(*href) {
        Ok(s) => {
            let upper = s.to_uppercase();
            match thread.heap_mut().alloc_string(&upper) {
                Ok(href) => PreHookResult::Bypass(Some(EmValue::ObjectRef(href))),
                Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
            }
        }
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.String.ToLower` method.
///
/// # Handled Overloads
///
/// - `String.ToLower() -> String`
/// - `String.ToLower(CultureInfo) -> String`
///
/// # Returns
///
/// A copy of the string converted to lowercase
fn string_to_lower_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let Some(EmValue::ObjectRef(href)) = ctx.this else {
        return PreHookResult::Bypass(Some(EmValue::Null));
    };

    match thread.heap().get_string(*href) {
        Ok(s) => {
            let lower = s.to_lowercase();
            match thread.heap_mut().alloc_string(&lower) {
                Ok(href) => PreHookResult::Bypass(Some(EmValue::ObjectRef(href))),
                Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
            }
        }
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.String.Trim` method.
///
/// # Handled Overloads
///
/// - `String.Trim() -> String`
/// - `String.Trim(Char[]) -> String`
///
/// # Parameters
///
/// - `trimChars`: Optional array of characters to trim (default whitespace)
///
/// # Returns
///
/// A new string with leading and trailing characters removed
fn string_trim_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let Some(EmValue::ObjectRef(href)) = ctx.this else {
        return PreHookResult::Bypass(Some(EmValue::Null));
    };

    match thread.heap().get_string(*href) {
        Ok(s) => {
            let trimmed = s.trim().to_string();
            match thread.heap_mut().alloc_string(&trimmed) {
                Ok(href) => PreHookResult::Bypass(Some(EmValue::ObjectRef(href))),
                Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
            }
        }
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.String.Replace` method.
///
/// # Handled Overloads
///
/// - `String.Replace(Char, Char) -> String`
/// - `String.Replace(String, String) -> String`
///
/// # Parameters
///
/// - `oldValue`: Character or string to be replaced
/// - `newValue`: Character or string to replace all occurrences
///
/// # Returns
///
/// A new string with all occurrences replaced
fn string_replace_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let Some(EmValue::ObjectRef(href)) = ctx.this else {
        return PreHookResult::Bypass(Some(EmValue::Null));
    };

    if ctx.args.len() < 2 {
        return PreHookResult::Bypass(Some(EmValue::ObjectRef(*href)));
    }

    let s = match thread.heap().get_string(*href) {
        Ok(s) => s.to_string(),
        Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
    };

    let result = match (&ctx.args[0], &ctx.args[1]) {
        (EmValue::Char(old), EmValue::Char(new)) => s.replace(*old, &new.to_string()),
        (EmValue::ObjectRef(old_ref), EmValue::ObjectRef(new_ref)) => {
            let old_str = thread
                .heap()
                .get_string(*old_ref)
                .map(|s| s.to_string())
                .unwrap_or_default();
            let new_str = thread
                .heap()
                .get_string(*new_ref)
                .map(|s| s.to_string())
                .unwrap_or_default();
            s.replace(&old_str, &new_str)
        }
        _ => s,
    };

    match thread.heap_mut().alloc_string(&result) {
        Ok(href) => PreHookResult::Bypass(Some(EmValue::ObjectRef(href))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.String.Split` method.
///
/// # Handled Overloads
///
/// - `String.Split(Char[]) -> String[]`
/// - `String.Split(Char[], Int32) -> String[]`
/// - `String.Split(Char[], StringSplitOptions) -> String[]`
///
/// # Parameters
///
/// - `separator`: Array of delimiter characters (or single char)
/// - `count`: Optional maximum number of substrings
/// - `options`: Optional split options
///
/// # Returns
///
/// An array of substrings delimited by the separator
fn string_split_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let Some(EmValue::ObjectRef(href)) = ctx.this else {
        return PreHookResult::Bypass(Some(EmValue::Null));
    };

    let s = match thread.heap().get_string(*href) {
        Ok(s) => s.to_string(),
        Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
    };

    let separator = match ctx.args.first() {
        Some(EmValue::Char(c)) => *c,
        Some(EmValue::ObjectRef(href)) => {
            if let Ok(HeapObject::Array { elements, .. }) = thread.heap().get(*href) {
                elements
                    .first()
                    .and_then(|e| {
                        if let EmValue::Char(c) = e {
                            Some(*c)
                        } else {
                            None
                        }
                    })
                    .unwrap_or(' ')
            } else {
                ' '
            }
        }
        _ => ' ',
    };

    let parts: Vec<&str> = s.split(separator).collect();
    let mut string_refs = Vec::with_capacity(parts.len());
    for part in parts {
        match thread.heap_mut().alloc_string(part) {
            Ok(string_ref) => string_refs.push(EmValue::ObjectRef(string_ref)),
            Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
        }
    }

    match thread
        .heap_mut()
        .alloc_array_with_values(CilFlavor::String, string_refs)
    {
        Ok(array_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(array_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.String.Contains` method.
///
/// # Handled Overloads
///
/// - `String.Contains(String) -> Boolean`
/// - `String.Contains(Char) -> Boolean`
///
/// # Parameters
///
/// - `value`: String or character to search for
///
/// # Returns
///
/// `true` if the value is found; otherwise `false`
fn string_contains_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let Some(EmValue::ObjectRef(href)) = ctx.this else {
        return PreHookResult::Bypass(Some(EmValue::Bool(false)));
    };

    let s = match thread.heap().get_string(*href) {
        Ok(s) => s.to_string(),
        Err(_) => return PreHookResult::Bypass(Some(EmValue::Bool(false))),
    };

    let contains = match ctx.args.first() {
        Some(EmValue::Char(c)) => s.contains(*c),
        Some(EmValue::ObjectRef(href)) => thread
            .heap()
            .get_string(*href)
            .map(|substr| s.contains(&*substr))
            .unwrap_or(false),
        _ => false,
    };

    PreHookResult::Bypass(Some(EmValue::Bool(contains)))
}

/// Hook for `System.String.StartsWith` method.
///
/// # Handled Overloads
///
/// - `String.StartsWith(String) -> Boolean`
/// - `String.StartsWith(String, StringComparison) -> Boolean`
/// - `String.StartsWith(Char) -> Boolean`
///
/// # Parameters
///
/// - `value`: String or character to compare
/// - `comparisonType`: Optional comparison rules
///
/// # Returns
///
/// `true` if the string starts with the value; otherwise `false`
fn string_starts_with_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let Some(EmValue::ObjectRef(href)) = ctx.this else {
        return PreHookResult::Bypass(Some(EmValue::Bool(false)));
    };

    let s = match thread.heap().get_string(*href) {
        Ok(s) => s.to_string(),
        Err(_) => return PreHookResult::Bypass(Some(EmValue::Bool(false))),
    };

    let starts_with = match ctx.args.first() {
        Some(EmValue::Char(c)) => s.starts_with(*c),
        Some(EmValue::ObjectRef(href)) => thread
            .heap()
            .get_string(*href)
            .map(|prefix| s.starts_with(&*prefix))
            .unwrap_or(false),
        _ => false,
    };

    PreHookResult::Bypass(Some(EmValue::Bool(starts_with)))
}

/// Hook for `System.String.EndsWith` method.
///
/// # Handled Overloads
///
/// - `String.EndsWith(String) -> Boolean`
/// - `String.EndsWith(String, StringComparison) -> Boolean`
/// - `String.EndsWith(Char) -> Boolean`
///
/// # Parameters
///
/// - `value`: String or character to compare
/// - `comparisonType`: Optional comparison rules
///
/// # Returns
///
/// `true` if the string ends with the value; otherwise `false`
fn string_ends_with_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let Some(EmValue::ObjectRef(href)) = ctx.this else {
        return PreHookResult::Bypass(Some(EmValue::Bool(false)));
    };

    let s = match thread.heap().get_string(*href) {
        Ok(s) => s.to_string(),
        Err(_) => return PreHookResult::Bypass(Some(EmValue::Bool(false))),
    };

    let ends_with = match ctx.args.first() {
        Some(EmValue::Char(c)) => s.ends_with(*c),
        Some(EmValue::ObjectRef(href)) => thread
            .heap()
            .get_string(*href)
            .map(|suffix| s.ends_with(&*suffix))
            .unwrap_or(false),
        _ => false,
    };

    PreHookResult::Bypass(Some(EmValue::Bool(ends_with)))
}

/// Hook for `System.String.IndexOf` method.
///
/// # Handled Overloads
///
/// - `String.IndexOf(Char) -> Int32`
/// - `String.IndexOf(String) -> Int32`
/// - `String.IndexOf(Char, Int32) -> Int32`
/// - `String.IndexOf(String, Int32) -> Int32`
///
/// # Parameters
///
/// - `value`: Character or string to search for
/// - `startIndex`: Optional starting search position
///
/// # Returns
///
/// Zero-based index of the first occurrence, or -1 if not found
fn string_index_of_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let Some(EmValue::ObjectRef(href)) = ctx.this else {
        return PreHookResult::Bypass(Some(EmValue::I32(-1)));
    };

    let s = match thread.heap().get_string(*href) {
        Ok(s) => s.to_string(),
        Err(_) => return PreHookResult::Bypass(Some(EmValue::I32(-1))),
    };

    let index = match ctx.args.first() {
        Some(EmValue::Char(c)) => s
            .find(*c)
            .map_or(-1, |i| i32::try_from(i).unwrap_or(i32::MAX)),
        Some(EmValue::ObjectRef(href)) => thread
            .heap()
            .get_string(*href)
            .map(|substr| {
                s.find(&*substr)
                    .map_or(-1, |i| i32::try_from(i).unwrap_or(i32::MAX))
            })
            .unwrap_or(-1),
        _ => -1,
    };

    PreHookResult::Bypass(Some(EmValue::I32(index)))
}

/// Hook for `System.String.PadLeft` method.
///
/// # Handled Overloads
///
/// - `String.PadLeft(Int32) -> String`
/// - `String.PadLeft(Int32, Char) -> String`
///
/// # Parameters
///
/// - `totalWidth`: Total length of resulting string
/// - `paddingChar`: Optional padding character (default space)
///
/// # Returns
///
/// A new string padded on the left to the specified width
fn string_pad_left_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let Some(EmValue::ObjectRef(href)) = ctx.this else {
        return PreHookResult::Bypass(Some(EmValue::Null));
    };

    let s = match thread.heap().get_string(*href) {
        Ok(s) => s.to_string(),
        Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
    };

    let total_width = ctx
        .args
        .first()
        .map(usize::try_from)
        .and_then(Result::ok)
        .unwrap_or(0);
    let pad_char = ctx
        .args
        .get(1)
        .and_then(|v| {
            if let EmValue::Char(c) = v {
                Some(*c)
            } else {
                None
            }
        })
        .unwrap_or(' ');

    let result = if s.len() >= total_width {
        s
    } else {
        let padding: String = std::iter::repeat_n(pad_char, total_width - s.len()).collect();
        format!("{padding}{s}")
    };

    match thread.heap_mut().alloc_string(&result) {
        Ok(href) => PreHookResult::Bypass(Some(EmValue::ObjectRef(href))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.String.PadRight` method.
///
/// # Handled Overloads
///
/// - `String.PadRight(Int32) -> String`
/// - `String.PadRight(Int32, Char) -> String`
///
/// # Parameters
///
/// - `totalWidth`: Total length of resulting string
/// - `paddingChar`: Optional padding character (default space)
///
/// # Returns
///
/// A new string padded on the right to the specified width
fn string_pad_right_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let Some(EmValue::ObjectRef(href)) = ctx.this else {
        return PreHookResult::Bypass(Some(EmValue::Null));
    };

    let s = match thread.heap().get_string(*href) {
        Ok(s) => s.to_string(),
        Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
    };

    let total_width = ctx
        .args
        .first()
        .map(usize::try_from)
        .and_then(Result::ok)
        .unwrap_or(0);
    let pad_char = ctx
        .args
        .get(1)
        .and_then(|v| {
            if let EmValue::Char(c) = v {
                Some(*c)
            } else {
                None
            }
        })
        .unwrap_or(' ');

    let result = if s.len() >= total_width {
        s
    } else {
        let padding: String = std::iter::repeat_n(pad_char, total_width - s.len()).collect();
        format!("{s}{padding}")
    };

    match thread.heap_mut().alloc_string(&result) {
        Ok(href) => PreHookResult::Bypass(Some(EmValue::ObjectRef(href))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.String.IsNullOrEmpty` static method.
///
/// # Handled Overloads
///
/// - `String.IsNullOrEmpty(String) -> Boolean`
///
/// # Parameters
///
/// - `value`: The string to test
///
/// # Returns
///
/// `true` if the string is null or empty; otherwise `false`
fn string_is_null_or_empty_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let is_null_or_empty = if let Some(EmValue::ObjectRef(href)) = ctx.args.first() {
        thread
            .heap()
            .get_string(*href)
            .map(|s| s.is_empty())
            .unwrap_or(true)
    } else {
        true
    };

    PreHookResult::Bypass(Some(EmValue::Bool(is_null_or_empty)))
}

/// Hook for `System.String.Join` static method.
///
/// # Handled Overloads
///
/// - `String.Join(String, String[]) -> String`
/// - `String.Join(String, Object[]) -> String`
/// - `String.Join(String, IEnumerable<String>) -> String`
///
/// # Parameters
///
/// - `separator`: String to insert between elements
/// - `value`: Array or collection of strings to join
///
/// # Returns
///
/// A single string with elements separated by the separator
fn string_join_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.len() < 2 {
        return PreHookResult::Bypass(Some(EmValue::Null));
    }

    let separator = if let EmValue::ObjectRef(href) = &ctx.args[0] {
        thread
            .heap()
            .get_string(*href)
            .map(|s| s.to_string())
            .unwrap_or_default()
    } else {
        String::new()
    };

    let array_ref = match &ctx.args[1] {
        EmValue::ObjectRef(r) => *r,
        _ => return PreHookResult::Bypass(Some(EmValue::Null)),
    };

    let obj = match thread.heap().get(array_ref) {
        Ok(o) => o,
        Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
    };

    let parts: Vec<String> = match obj {
        HeapObject::Array { elements, .. } => elements
            .iter()
            .filter_map(|e| match e {
                EmValue::ObjectRef(href) => {
                    thread.heap().get_string(*href).ok().map(|s| s.to_string())
                }
                EmValue::Null => Some(String::new()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    };

    let result = parts.join(&separator);
    match thread.heap_mut().alloc_string(&result) {
        Ok(href) => PreHookResult::Bypass(Some(EmValue::ObjectRef(href))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.String.Format` static method.
///
/// # Handled Overloads
///
/// - `String.Format(String, Object) -> String`
/// - `String.Format(String, Object, Object) -> String`
/// - `String.Format(String, Object, Object, Object) -> String`
/// - `String.Format(String, Object[]) -> String`
///
/// # Parameters
///
/// - `format`: Composite format string with placeholders like `{0}`, `{1}`
/// - `args`: Objects to format into the placeholders
///
/// # Returns
///
/// A formatted string with placeholders replaced by argument values
fn string_format_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::Null));
    }

    let format_str = match &ctx.args[0] {
        EmValue::ObjectRef(href) => match thread.heap().get_string(*href) {
            Ok(s) => s.to_string(),
            Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
        },
        _ => return PreHookResult::Bypass(Some(EmValue::Null)),
    };

    let mut result = format_str;
    for (i, arg) in ctx.args.iter().skip(1).enumerate() {
        let placeholder = format!("{{{i}}}");
        let value_str = match arg {
            EmValue::ObjectRef(href) => thread
                .heap()
                .get_string(*href)
                .map(|s| s.to_string())
                .unwrap_or_else(|_| "[object]".to_string()),
            EmValue::Null => String::new(),
            EmValue::I32(v) => v.to_string(),
            EmValue::I64(v) => v.to_string(),
            EmValue::F32(v) => v.to_string(),
            EmValue::F64(v) => v.to_string(),
            EmValue::Bool(v) => if *v { "True" } else { "False" }.to_string(),
            EmValue::Char(c) => c.to_string(),
            _ => "[value]".to_string(),
        };
        result = result.replace(&placeholder, &value_str);
    }

    match thread.heap_mut().alloc_string(&result) {
        Ok(href) => PreHookResult::Bypass(Some(EmValue::ObjectRef(href))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.String.Intern` static method.
///
/// # Handled Overloads
///
/// - `String.Intern(String) -> String`
///
/// # Parameters
///
/// - `str`: The string to intern
///
/// # Returns
///
/// The interned string (in our emulation, we just return the same string)
///
/// # Notes
///
/// In the CLR, interning ensures that all strings with the same content share
/// the same reference. For emulation purposes, we simply pass through the string.
fn string_intern_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    // Simply return the input string - we don't need actual interning for emulation
    if let Some(s) = ctx.args.first() {
        PreHookResult::Bypass(Some(s.clone()))
    } else {
        PreHookResult::Bypass(Some(EmValue::Null))
    }
}

/// Hook for `System.String.IsInterned` static method.
///
/// # Handled Overloads
///
/// - `String.IsInterned(String) -> String`
///
/// # Parameters
///
/// - `str`: The string to check
///
/// # Returns
///
/// The interned string if found, or null if not interned.
/// For emulation, we assume all strings are interned.
fn string_is_interned_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    // Return the input string (assume all strings are interned)
    if let Some(s) = ctx.args.first() {
        PreHookResult::Bypass(Some(s.clone()))
    } else {
        PreHookResult::Bypass(Some(EmValue::Null))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        emulation::runtime::hook::HookManager,
        metadata::{token::Token, typesystem::PointerSize},
        test::emulation::create_test_thread,
    };

    #[test]
    fn test_register_hooks() {
        let mut manager = HookManager::new();
        register(&mut manager);
        assert_eq!(manager.len(), 21);
    }

    #[test]
    fn test_string_concat_hook() {
        let mut thread = create_test_thread();
        let s1 = thread.heap_mut().alloc_string("Hello ").unwrap();
        let s2 = thread.heap_mut().alloc_string("World").unwrap();

        let args = [EmValue::ObjectRef(s1), EmValue::ObjectRef(s2)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "String",
            "Concat",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let result = string_concat_pre(&ctx, &mut thread);

        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) = result {
            assert_eq!(&*thread.heap().get_string(r).unwrap(), "Hello World");
        } else {
            panic!("Expected Bypass with ObjectRef");
        }
    }

    #[test]
    fn test_string_length_hook() {
        let mut thread = create_test_thread();
        let s = thread.heap_mut().alloc_string("Hello").unwrap();

        let this = EmValue::ObjectRef(s);
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "String",
            "get_Length",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));

        let result = string_get_length_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(5)))
        ));
    }

    #[test]
    fn test_string_to_upper_hook() {
        let mut thread = create_test_thread();
        let s = thread.heap_mut().alloc_string("hello").unwrap();

        let this = EmValue::ObjectRef(s);
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "String",
            "ToUpper",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));

        let result = string_to_upper_pre(&ctx, &mut thread);

        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) = result {
            assert_eq!(&*thread.heap().get_string(r).unwrap(), "HELLO");
        } else {
            panic!("Expected Bypass with ObjectRef");
        }
    }

    #[test]
    fn test_string_is_null_or_empty_hook() {
        let mut thread = create_test_thread();
        let empty = thread.heap_mut().alloc_string("").unwrap();
        let non_empty = thread.heap_mut().alloc_string("test").unwrap();

        // Test null
        let args = [EmValue::Null];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "String",
            "IsNullOrEmpty",
            PointerSize::Bit64,
        )
        .with_args(&args);
        let result = string_is_null_or_empty_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::Bool(true)))
        ));

        // Test empty
        let args = [EmValue::ObjectRef(empty)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "String",
            "IsNullOrEmpty",
            PointerSize::Bit64,
        )
        .with_args(&args);
        let result = string_is_null_or_empty_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::Bool(true)))
        ));

        // Test non-empty
        let args = [EmValue::ObjectRef(non_empty)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "String",
            "IsNullOrEmpty",
            PointerSize::Bit64,
        )
        .with_args(&args);
        let result = string_is_null_or_empty_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::Bool(false)))
        ));
    }
}
