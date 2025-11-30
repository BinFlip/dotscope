//! DOT format utilities for graph visualization.
//!
//! This module provides utilities for generating DOT format output,
//! which can be rendered using Graphviz tools.

/// Escapes a string for safe use in DOT format labels and identifiers.
///
/// This function handles all characters that have special meaning in DOT format,
/// including quotes, backslashes, newlines, and angle brackets.
///
/// # Arguments
///
/// * `s` - The string to escape
///
/// # Returns
///
/// A new string with all special characters properly escaped.
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::utils::escape_dot;
///
/// let escaped = escape_dot("Method<T>");
/// assert_eq!(escaped, "Method\\<T\\>");
/// ```
#[must_use]
pub fn escape_dot(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "")
        .replace('<', "\\<")
        .replace('>', "\\>")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_dot_basic() {
        assert_eq!(escape_dot("hello"), "hello");
    }

    #[test]
    fn test_escape_dot_quotes() {
        assert_eq!(escape_dot("say \"hello\""), "say \\\"hello\\\"");
    }

    #[test]
    fn test_escape_dot_backslash() {
        assert_eq!(escape_dot("path\\to\\file"), "path\\\\to\\\\file");
    }

    #[test]
    fn test_escape_dot_newlines() {
        assert_eq!(escape_dot("line1\nline2"), "line1\\nline2");
        assert_eq!(escape_dot("line1\r\nline2"), "line1\\nline2");
    }

    #[test]
    fn test_escape_dot_angle_brackets() {
        assert_eq!(escape_dot("List<T>"), "List\\<T\\>");
    }

    #[test]
    fn test_escape_dot_combined() {
        assert_eq!(
            escape_dot("Method<T>(\"arg\")"),
            "Method\\<T\\>(\\\"arg\\\")"
        );
    }
}
