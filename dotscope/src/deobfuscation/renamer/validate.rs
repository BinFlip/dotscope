//! Identifier validation and normalization for renamed identifiers.
//!
//! Ensures that generated names are valid .NET identifiers and do not
//! collide with C# reserved keywords.

use std::collections::HashMap;

use crate::deobfuscation::renamer::context::IdentifierKind;

/// Validates and normalizes a suggested name.
///
/// Applies the following checks and transformations in order:
/// 1. Strip leading/trailing whitespace, quotes, backticks, markdown artifacts
/// 2. Reject empty names
/// 3. Reject C# reserved keywords
/// 4. Validate as .NET identifier (letter/underscore start, alphanumeric body)
/// 5. Truncate to `max_length`
/// 6. Apply appropriate casing (PascalCase for types/methods, camelCase for fields/params)
///
/// # Arguments
///
/// * `name` - The raw name string to validate.
/// * `kind` - The identifier kind, which determines casing convention.
/// * `max_length` - Maximum allowed length for the resulting name.
///
/// # Returns
///
/// The validated and normalized name, or `None` if the name cannot be salvaged.
pub fn validate_name(name: &str, kind: IdentifierKind, max_length: usize) -> Option<String> {
    // Strip common LLM artifacts
    let cleaned = name
        .trim()
        .trim_matches(|c: char| c == '"' || c == '\'' || c == '`' || c == '*');

    if cleaned.is_empty() {
        return None;
    }

    // Reject keywords
    if is_csharp_keyword(cleaned) {
        return None;
    }

    // Must be a valid .NET identifier
    if !is_valid_dotnet_identifier(cleaned) {
        return None;
    }

    // Truncate
    let truncated = if cleaned.len() > max_length {
        &cleaned[..max_length]
    } else {
        cleaned
    };

    // Apply casing convention
    let result = match kind {
        IdentifierKind::Type | IdentifierKind::Method => to_pascal_case(truncated),
        IdentifierKind::Field | IdentifierKind::Parameter => to_camel_case(truncated),
    };

    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

/// Checks if a string is a valid .NET identifier.
///
/// Rules (ECMA-335 + C# spec):
/// - Must start with a letter (Unicode) or underscore
/// - Subsequent characters must be letters, digits, or underscores
/// - Must not be empty
///
/// # Arguments
///
/// * `name` - The identifier string to validate.
///
/// # Returns
///
/// `true` if the name is a valid .NET identifier, `false` otherwise.
pub fn is_valid_dotnet_identifier(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }

    let mut chars = name.chars();

    // First character: letter or underscore
    let first = chars.next().unwrap();
    if !first.is_alphabetic() && first != '_' {
        return false;
    }

    // Remaining characters: letter, digit, or underscore
    chars.all(|c| c.is_alphanumeric() || c == '_')
}

/// Checks if a name is a C# reserved keyword.
///
/// Covers all C# keywords that cannot be used as unescaped identifiers.
///
/// # Arguments
///
/// * `name` - The name to check.
///
/// # Returns
///
/// `true` if the name is a C# keyword, `false` otherwise.
pub fn is_csharp_keyword(name: &str) -> bool {
    matches!(
        name,
        "abstract"
            | "as"
            | "base"
            | "bool"
            | "break"
            | "byte"
            | "case"
            | "catch"
            | "char"
            | "checked"
            | "class"
            | "const"
            | "continue"
            | "decimal"
            | "default"
            | "delegate"
            | "do"
            | "double"
            | "else"
            | "enum"
            | "event"
            | "explicit"
            | "extern"
            | "false"
            | "finally"
            | "fixed"
            | "float"
            | "for"
            | "foreach"
            | "goto"
            | "if"
            | "implicit"
            | "in"
            | "int"
            | "interface"
            | "internal"
            | "is"
            | "lock"
            | "long"
            | "namespace"
            | "new"
            | "null"
            | "object"
            | "operator"
            | "out"
            | "override"
            | "params"
            | "private"
            | "protected"
            | "public"
            | "readonly"
            | "ref"
            | "return"
            | "sbyte"
            | "sealed"
            | "short"
            | "sizeof"
            | "stackalloc"
            | "static"
            | "string"
            | "struct"
            | "switch"
            | "this"
            | "throw"
            | "true"
            | "try"
            | "typeof"
            | "uint"
            | "ulong"
            | "unchecked"
            | "unsafe"
            | "ushort"
            | "using"
            | "virtual"
            | "void"
            | "volatile"
            | "while"
    )
}

/// Converts a name to PascalCase.
///
/// If the first character is lowercase, uppercases it. Otherwise returns as-is.
///
/// # Arguments
///
/// * `name` - The name to convert.
///
/// # Returns
///
/// The PascalCase version of the name, or an empty string if input is empty.
pub fn to_pascal_case(name: &str) -> String {
    if name.is_empty() {
        return String::new();
    }

    let mut chars = name.chars();
    let first = chars.next().unwrap();
    if first.is_lowercase() {
        let upper: String = first.to_uppercase().collect();
        format!("{upper}{}", chars.as_str())
    } else {
        name.to_string()
    }
}

/// Converts a name to camelCase.
///
/// If the first character is uppercase, lowercases it. Otherwise returns as-is.
///
/// # Arguments
///
/// * `name` - The name to convert.
///
/// # Returns
///
/// The camelCase version of the name, or an empty string if input is empty.
pub fn to_camel_case(name: &str) -> String {
    if name.is_empty() {
        return String::new();
    }

    let mut chars = name.chars();
    let first = chars.next().unwrap();
    if first.is_uppercase() {
        let lower: String = first.to_lowercase().collect();
        format!("{lower}{}", chars.as_str())
    } else {
        name.to_string()
    }
}

/// Resolves name conflicts within a scope by appending numeric suffixes.
///
/// Given a set of proposed names and a set of existing names in the scope,
/// appends `_2`, `_3`, etc. to any duplicates until all names are unique.
///
/// # Arguments
///
/// * `proposed` - Mutable slice of proposed names to deconflict in-place.
/// * `existing` - Names already used in this scope that must not be reused.
pub fn deconflict_names(proposed: &mut [String], existing: &[String]) {
    let mut used: HashMap<String, usize> = HashMap::new();

    // Reserve existing names
    for name in existing {
        used.insert(name.clone(), 1);
    }

    for name in proposed.iter_mut() {
        let count = used.entry(name.clone()).or_insert(0);
        *count += 1;
        if *count > 1 {
            let mut suffix = *count;
            loop {
                let candidate = format!("{name}_{suffix}");
                if !used.contains_key(&candidate) {
                    used.insert(candidate.clone(), 1);
                    *name = candidate;
                    break;
                }
                suffix += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::deobfuscation::renamer::{
        context::IdentifierKind,
        validate::{
            deconflict_names, is_csharp_keyword, is_valid_dotnet_identifier, to_camel_case,
            to_pascal_case, validate_name,
        },
    };

    /// Default max name length used in tests.
    const TEST_MAX_LENGTH: usize = 64;

    #[test]
    fn test_validate_name_basic() {
        // Valid names pass through
        assert_eq!(
            validate_name("MyClass", IdentifierKind::Type, TEST_MAX_LENGTH),
            Some("MyClass".to_string())
        );
        assert_eq!(
            validate_name("processData", IdentifierKind::Method, TEST_MAX_LENGTH),
            Some("ProcessData".to_string())
        );
        assert_eq!(
            validate_name("ConfigPath", IdentifierKind::Field, TEST_MAX_LENGTH),
            Some("configPath".to_string())
        );

        // Empty/whitespace rejected
        assert_eq!(
            validate_name("", IdentifierKind::Type, TEST_MAX_LENGTH),
            None
        );
        assert_eq!(
            validate_name("   ", IdentifierKind::Type, TEST_MAX_LENGTH),
            None
        );

        // Keywords rejected
        assert_eq!(
            validate_name("class", IdentifierKind::Type, TEST_MAX_LENGTH),
            None
        );
        assert_eq!(
            validate_name("return", IdentifierKind::Method, TEST_MAX_LENGTH),
            None
        );

        // Invalid identifiers rejected
        assert_eq!(
            validate_name("123abc", IdentifierKind::Type, TEST_MAX_LENGTH),
            None
        );
        assert_eq!(
            validate_name("a b c", IdentifierKind::Method, TEST_MAX_LENGTH),
            None
        );

        // LLM artifacts stripped
        assert_eq!(
            validate_name("\"MyClass\"", IdentifierKind::Type, TEST_MAX_LENGTH),
            Some("MyClass".to_string())
        );
        assert_eq!(
            validate_name("`fieldName`", IdentifierKind::Field, TEST_MAX_LENGTH),
            Some("fieldName".to_string())
        );
    }

    #[test]
    fn test_validate_name_csharp_keywords() {
        let keywords = [
            "abstract",
            "as",
            "base",
            "bool",
            "break",
            "byte",
            "case",
            "catch",
            "char",
            "checked",
            "class",
            "const",
            "continue",
            "decimal",
            "default",
            "delegate",
            "do",
            "double",
            "else",
            "enum",
            "event",
            "explicit",
            "extern",
            "false",
            "finally",
            "fixed",
            "float",
            "for",
            "foreach",
            "goto",
            "if",
            "implicit",
            "in",
            "int",
            "interface",
            "internal",
            "is",
            "lock",
            "long",
            "namespace",
            "new",
            "null",
            "object",
            "operator",
            "out",
            "override",
            "params",
            "private",
            "protected",
            "public",
            "readonly",
            "ref",
            "return",
            "sbyte",
            "sealed",
            "short",
            "sizeof",
            "stackalloc",
            "static",
            "string",
            "struct",
            "switch",
            "this",
            "throw",
            "true",
            "try",
            "typeof",
            "uint",
            "ulong",
            "unchecked",
            "unsafe",
            "ushort",
            "using",
            "virtual",
            "void",
            "volatile",
            "while",
        ];
        for kw in &keywords {
            assert!(is_csharp_keyword(kw), "Expected '{kw}' to be a C# keyword");
            assert_eq!(
                validate_name(kw, IdentifierKind::Type, TEST_MAX_LENGTH),
                None,
                "Keyword '{kw}' should be rejected"
            );
        }
    }

    #[test]
    fn test_validate_name_length_limit() {
        let long_name = "A".repeat(100);
        let result = validate_name(&long_name, IdentifierKind::Type, 64).unwrap();
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn test_validate_name_custom_max_length() {
        let name = "A".repeat(30);
        let result = validate_name(&name, IdentifierKind::Type, 10).unwrap();
        assert_eq!(result.len(), 10);
    }

    #[test]
    fn test_is_valid_dotnet_identifier() {
        assert!(is_valid_dotnet_identifier("MyClass"));
        assert!(is_valid_dotnet_identifier("_private"));
        assert!(is_valid_dotnet_identifier("a1"));
        assert!(is_valid_dotnet_identifier("_"));

        assert!(!is_valid_dotnet_identifier(""));
        assert!(!is_valid_dotnet_identifier("1abc"));
        assert!(!is_valid_dotnet_identifier("a b"));
        assert!(!is_valid_dotnet_identifier("a-b"));
        assert!(!is_valid_dotnet_identifier("a.b"));
    }

    #[test]
    fn test_to_pascal_case() {
        assert_eq!(to_pascal_case("hello"), "Hello");
        assert_eq!(to_pascal_case("Hello"), "Hello");
        assert_eq!(to_pascal_case("helloWorld"), "HelloWorld");
        assert_eq!(to_pascal_case(""), "");
    }

    #[test]
    fn test_to_camel_case() {
        assert_eq!(to_camel_case("Hello"), "hello");
        assert_eq!(to_camel_case("hello"), "hello");
        assert_eq!(to_camel_case("HelloWorld"), "helloWorld");
        assert_eq!(to_camel_case(""), "");
    }

    #[test]
    fn test_deconflict_names() {
        let mut proposed = vec![
            "Config".to_string(),
            "Config".to_string(),
            "Config".to_string(),
        ];
        let existing = vec!["Existing".to_string()];
        deconflict_names(&mut proposed, &existing);

        assert_eq!(proposed[0], "Config");
        assert_eq!(proposed[1], "Config_2");
        assert_eq!(proposed[2], "Config_3");

        // Existing names are respected
        let mut proposed2 = vec!["Existing".to_string()];
        deconflict_names(&mut proposed2, &existing);
        assert_eq!(proposed2[0], "Existing_2");
    }
}
