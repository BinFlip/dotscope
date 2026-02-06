//! Diagnostics collection for assembly loading and analysis.
//!
//! This module provides types for collecting and reporting diagnostic messages
//! during assembly loading. It supports lenient loading scenarios where malformed
//! or obfuscated assemblies may contain invalid metadata that should be reported
//! but not prevent loading from continuing.
//!
//! # Architecture
//!
//! The diagnostics system is designed to be shared across the loading pipeline:
//! - **CilAssemblyView**: Reports structural issues (duplicate heaps, etc.)
//! - **CilObject**: Reports resolution issues (invalid indices, parse failures)
//! - **Validation**: Reports validation violations in lenient mode
//!
//! The [`Diagnostics`] container uses `boxcar::Vec` for thread-safe, lock-free
//! append operations, allowing diagnostics to be collected from parallel loading
//! operations without synchronization overhead.
//!
//! # Key Components
//!
//! - [`Diagnostics`] - Thread-safe container for diagnostic entries
//! - [`Diagnostic`] - Individual diagnostic entry with severity and context
//! - [`DiagnosticSeverity`] - Severity level (Info, Warning, Error)
//! - [`DiagnosticCategory`] - Category of the diagnostic source
//!
//! # Usage Examples
//!
//! ## Collecting Diagnostics During Loading
//!
//! ```rust,no_run
//! use dotscope::metadata::diagnostics::{Diagnostics, DiagnosticSeverity, DiagnosticCategory};
//! use std::sync::Arc;
//!
//! let diagnostics = Arc::new(Diagnostics::new());
//!
//! // Report an invalid heap index
//! diagnostics.warning(
//!     DiagnosticCategory::Heap,
//!     "Invalid string heap index 0x7fff7fff in Module table row 2",
//! );
//!
//! // Report a parse error
//! diagnostics.error(
//!     DiagnosticCategory::CustomAttribute,
//!     "Failed to parse custom attribute blob at index 0x1234: too many named arguments",
//! );
//!
//! // Check if any diagnostics were collected
//! if diagnostics.has_errors() {
//!     println!("Errors found: {}", diagnostics.error_count());
//! }
//!
//! // Iterate over all diagnostics
//! for entry in diagnostics.iter() {
//!     println!("[{:?}] {}: {}", entry.severity, entry.category, entry.message);
//! }
//! ```
//!
//! ## Filtering by Category
//!
//! ```rust,no_run
//! use dotscope::metadata::diagnostics::{Diagnostics, DiagnosticCategory};
//! use std::sync::Arc;
//!
//! let diagnostics = Arc::new(Diagnostics::new());
//! // ... loading happens ...
//!
//! // Get only custom attribute related diagnostics
//! let ca_issues: Vec<_> = diagnostics
//!     .iter()
//!     .filter(|d| d.category == DiagnosticCategory::CustomAttribute)
//!     .collect();
//!
//! println!("Custom attribute issues: {}", ca_issues.len());
//! ```
//!
//! # Thread Safety
//!
//! All types in this module are [`Send`] and [`Sync`]. The [`Diagnostics`] container
//! uses `boxcar::Vec` internally, which provides lock-free concurrent append operations.
//! Multiple threads can safely add diagnostics simultaneously without coordination.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::cilassemblyview`] - Reports structural anomalies
//! - [`crate::metadata::cilobject`] - Reports resolution and parsing failures
//! - [`crate::metadata::validation`] - Reports validation violations in lenient mode

use std::fmt::{self, Write};

/// Severity level of a diagnostic entry.
///
/// Determines how the diagnostic should be treated and displayed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiagnosticSeverity {
    /// Informational message, not indicating a problem.
    ///
    /// Used for noting unusual but valid constructs.
    Info,

    /// Warning about potentially problematic metadata.
    ///
    /// The assembly can still be loaded and analyzed, but some data
    /// may be missing, placeholder values may be used, or behavior
    /// may differ from a well-formed assembly.
    Warning,

    /// Error indicating invalid or corrupt metadata.
    ///
    /// In lenient mode, loading continues but the affected data
    /// is unavailable or replaced with placeholders. In strict mode,
    /// this would cause loading to abort.
    Error,
}

impl fmt::Display for DiagnosticSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DiagnosticSeverity::Info => write!(f, "INFO"),
            DiagnosticSeverity::Warning => write!(f, "WARN"),
            DiagnosticSeverity::Error => write!(f, "ERROR"),
        }
    }
}

/// Category indicating the source or type of diagnostic.
///
/// Helps classify diagnostics for filtering and reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiagnosticCategory {
    /// Issues with metadata heap streams (strings, blob, GUID, user strings).
    ///
    /// Examples: duplicate heap names, invalid heap structure.
    Heap,

    /// Issues with metadata table structure or content.
    ///
    /// Examples: invalid row counts, malformed table data.
    Table,

    /// Issues with custom attribute parsing.
    ///
    /// Examples: invalid blob index, malformed attribute blob, parse failures.
    CustomAttribute,

    /// Issues with type/method/field signature parsing.
    ///
    /// Examples: invalid signature blob, unsupported calling conventions.
    Signature,

    /// Issues with type resolution.
    ///
    /// Examples: unresolvable type references, circular dependencies.
    Type,

    /// Issues with method resolution or IL parsing.
    ///
    /// Examples: invalid method body, unresolvable method references.
    Method,

    /// Issues with field resolution.
    ///
    /// Examples: invalid field references, layout conflicts.
    Field,

    /// Issues found during validation.
    ///
    /// Examples: semantic rule violations, cross-reference inconsistencies.
    Validation,

    /// General loading issues not fitting other categories.
    ///
    /// Examples: PE structure issues, metadata root problems.
    General,
}

impl fmt::Display for DiagnosticCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DiagnosticCategory::Heap => write!(f, "Heap"),
            DiagnosticCategory::Table => write!(f, "Table"),
            DiagnosticCategory::CustomAttribute => write!(f, "CustomAttribute"),
            DiagnosticCategory::Signature => write!(f, "Signature"),
            DiagnosticCategory::Type => write!(f, "Type"),
            DiagnosticCategory::Method => write!(f, "Method"),
            DiagnosticCategory::Field => write!(f, "Field"),
            DiagnosticCategory::Validation => write!(f, "Validation"),
            DiagnosticCategory::General => write!(f, "General"),
        }
    }
}

/// A single diagnostic entry with context information.
///
/// Contains the severity, category, message, and optional location information
/// for a diagnostic reported during assembly loading or analysis.
#[derive(Debug, Clone)]
pub struct Diagnostic {
    /// Severity level of this diagnostic.
    pub severity: DiagnosticSeverity,

    /// Category indicating the source of this diagnostic.
    pub category: DiagnosticCategory,

    /// Human-readable description of the issue.
    pub message: String,

    /// Optional file offset where the issue was found.
    pub offset: Option<u64>,

    /// Optional metadata token related to the issue.
    pub token: Option<u32>,

    /// Optional table and row information (table_id, row_index).
    pub table_row: Option<(u8, u32)>,
}

impl Diagnostic {
    /// Creates a new diagnostic entry.
    ///
    /// # Arguments
    ///
    /// * `severity` - Severity level of the diagnostic
    /// * `category` - Category of the diagnostic source
    /// * `message` - Human-readable description
    pub fn new(
        severity: DiagnosticSeverity,
        category: DiagnosticCategory,
        message: impl Into<String>,
    ) -> Self {
        Self {
            severity,
            category,
            message: message.into(),
            offset: None,
            token: None,
            table_row: None,
        }
    }

    /// Adds file offset information to the diagnostic.
    #[must_use]
    pub fn with_offset(mut self, offset: u64) -> Self {
        self.offset = Some(offset);
        self
    }

    /// Adds metadata token information to the diagnostic.
    #[must_use]
    pub fn with_token(mut self, token: u32) -> Self {
        self.token = Some(token);
        self
    }

    /// Adds table/row information to the diagnostic.
    #[must_use]
    pub fn with_table_row(mut self, table_id: u8, row_index: u32) -> Self {
        self.table_row = Some((table_id, row_index));
        self
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}: {}", self.severity, self.category, self.message)?;

        if let Some(offset) = self.offset {
            write!(f, " (offset: 0x{:08x})", offset)?;
        }

        if let Some(token) = self.token {
            write!(f, " (token: 0x{:08x})", token)?;
        }

        if let Some((table_id, row)) = self.table_row {
            write!(f, " (table: 0x{:02x}, row: {})", table_id, row)?;
        }

        Ok(())
    }
}

/// Thread-safe container for collecting diagnostic entries.
///
/// Uses `boxcar::Vec` internally for lock-free concurrent append operations.
/// Multiple threads can safely add diagnostics simultaneously.
///
/// # Example
///
/// ```rust,no_run
/// use dotscope::metadata::diagnostics::{Diagnostics, DiagnosticCategory};
/// use std::sync::Arc;
///
/// let diagnostics = Arc::new(Diagnostics::new());
///
/// // Can be cloned and shared across threads
/// let diag_clone = Arc::clone(&diagnostics);
/// std::thread::spawn(move || {
///     diag_clone.warning(DiagnosticCategory::Heap, "Duplicate heap stream");
/// });
///
/// // Original can still be used
/// diagnostics.error(DiagnosticCategory::Table, "Invalid table row");
/// ```
#[derive(Debug)]
pub struct Diagnostics {
    entries: boxcar::Vec<Diagnostic>,
}

impl Default for Diagnostics {
    fn default() -> Self {
        Self::new()
    }
}

impl Diagnostics {
    /// Creates a new empty diagnostics container.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: boxcar::Vec::new(),
        }
    }

    /// Adds an informational diagnostic.
    ///
    /// # Arguments
    ///
    /// * `category` - Category of the diagnostic
    /// * `message` - Description of the observation
    pub fn info(&self, category: DiagnosticCategory, message: impl Into<String>) {
        self.push(Diagnostic::new(DiagnosticSeverity::Info, category, message));
    }

    /// Adds a warning diagnostic.
    ///
    /// # Arguments
    ///
    /// * `category` - Category of the diagnostic
    /// * `message` - Description of the issue
    pub fn warning(&self, category: DiagnosticCategory, message: impl Into<String>) {
        self.push(Diagnostic::new(
            DiagnosticSeverity::Warning,
            category,
            message,
        ));
    }

    /// Adds an error diagnostic.
    ///
    /// # Arguments
    ///
    /// * `category` - Category of the diagnostic
    /// * `message` - Description of the error
    pub fn error(&self, category: DiagnosticCategory, message: impl Into<String>) {
        self.push(Diagnostic::new(
            DiagnosticSeverity::Error,
            category,
            message,
        ));
    }

    /// Adds a diagnostic entry directly.
    ///
    /// Use this for diagnostics that need additional context like
    /// offset, token, or table/row information.
    pub fn push(&self, diagnostic: Diagnostic) {
        self.entries.push(diagnostic);
    }

    /// Returns true if any diagnostics have been collected.
    pub fn has_any(&self) -> bool {
        self.entries.count() > 0
    }

    /// Returns true if any error-level diagnostics have been collected.
    pub fn has_errors(&self) -> bool {
        self.entries
            .iter()
            .any(|(_, d)| d.severity == DiagnosticSeverity::Error)
    }

    /// Returns true if any warning-level diagnostics have been collected.
    pub fn has_warnings(&self) -> bool {
        self.entries
            .iter()
            .any(|(_, d)| d.severity == DiagnosticSeverity::Warning)
    }

    /// Returns the total number of diagnostics.
    pub fn count(&self) -> usize {
        self.entries.count()
    }

    /// Returns the number of error-level diagnostics.
    pub fn error_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|(_, d)| d.severity == DiagnosticSeverity::Error)
            .count()
    }

    /// Returns the number of warning-level diagnostics.
    pub fn warning_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|(_, d)| d.severity == DiagnosticSeverity::Warning)
            .count()
    }

    /// Returns the number of info-level diagnostics.
    pub fn info_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|(_, d)| d.severity == DiagnosticSeverity::Info)
            .count()
    }

    /// Returns an iterator over all diagnostics.
    ///
    /// Note: Uses boxcar's iterator which yields `(index, &Diagnostic)` tuples.
    /// The index can be ignored in most cases.
    pub fn iter(&self) -> impl Iterator<Item = &Diagnostic> {
        self.entries.iter().map(|(_, d)| d)
    }

    /// Returns all errors as a vector.
    pub fn errors(&self) -> Vec<&Diagnostic> {
        self.entries
            .iter()
            .filter(|(_, d)| d.severity == DiagnosticSeverity::Error)
            .map(|(_, d)| d)
            .collect()
    }

    /// Returns all warnings as a vector.
    pub fn warnings(&self) -> Vec<&Diagnostic> {
        self.entries
            .iter()
            .filter(|(_, d)| d.severity == DiagnosticSeverity::Warning)
            .map(|(_, d)| d)
            .collect()
    }

    /// Returns diagnostics filtered by category.
    pub fn by_category(&self, category: DiagnosticCategory) -> Vec<&Diagnostic> {
        self.entries
            .iter()
            .filter(|(_, d)| d.category == category)
            .map(|(_, d)| d)
            .collect()
    }

    /// Formats a summary of all diagnostics for display.
    ///
    /// Groups diagnostics by category and severity for readable output.
    pub fn summary(&self) -> String {
        let mut output = String::new();

        let error_count = self.error_count();
        let warning_count = self.warning_count();
        let info_count = self.info_count();

        let _ = writeln!(
            output,
            "Diagnostics: {} error(s), {} warning(s), {} info(s)",
            error_count, warning_count, info_count
        );

        if error_count > 0 {
            output.push_str("\nErrors:\n");
            for diag in self.errors() {
                let _ = writeln!(output, "  {diag}");
            }
        }

        if warning_count > 0 {
            output.push_str("\nWarnings:\n");
            for diag in self.warnings() {
                let _ = writeln!(output, "  {diag}");
            }
        }

        output
    }
}

impl fmt::Display for Diagnostics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_diagnostic_creation() {
        let diag = Diagnostic::new(
            DiagnosticSeverity::Warning,
            DiagnosticCategory::Heap,
            "Test message",
        );

        assert_eq!(diag.severity, DiagnosticSeverity::Warning);
        assert_eq!(diag.category, DiagnosticCategory::Heap);
        assert_eq!(diag.message, "Test message");
        assert!(diag.offset.is_none());
        assert!(diag.token.is_none());
        assert!(diag.table_row.is_none());
    }

    #[test]
    fn test_diagnostic_with_context() {
        let diag = Diagnostic::new(
            DiagnosticSeverity::Error,
            DiagnosticCategory::Table,
            "Invalid row",
        )
        .with_offset(0x1000)
        .with_token(0x06000001)
        .with_table_row(0x06, 1);

        assert_eq!(diag.offset, Some(0x1000));
        assert_eq!(diag.token, Some(0x06000001));
        assert_eq!(diag.table_row, Some((0x06, 1)));
    }

    #[test]
    fn test_diagnostics_container() {
        let diagnostics = Diagnostics::new();

        diagnostics.info(DiagnosticCategory::General, "Info message");
        diagnostics.warning(DiagnosticCategory::Heap, "Warning message");
        diagnostics.error(DiagnosticCategory::Table, "Error message");

        assert_eq!(diagnostics.count(), 3);
        assert_eq!(diagnostics.error_count(), 1);
        assert_eq!(diagnostics.warning_count(), 1);
        assert_eq!(diagnostics.info_count(), 1);
        assert!(diagnostics.has_errors());
        assert!(diagnostics.has_warnings());
        assert!(diagnostics.has_any());
    }

    #[test]
    fn test_diagnostics_thread_safety() {
        let diagnostics = Arc::new(Diagnostics::new());
        let mut handles = vec![];

        for i in 0..10 {
            let diag_clone = Arc::clone(&diagnostics);
            handles.push(thread::spawn(move || {
                diag_clone.warning(DiagnosticCategory::General, format!("Thread {} warning", i));
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(diagnostics.count(), 10);
    }

    #[test]
    fn test_diagnostics_by_category() {
        let diagnostics = Diagnostics::new();

        diagnostics.error(DiagnosticCategory::Heap, "Heap error 1");
        diagnostics.error(DiagnosticCategory::Heap, "Heap error 2");
        diagnostics.error(DiagnosticCategory::Table, "Table error");
        diagnostics.warning(DiagnosticCategory::Heap, "Heap warning");

        let heap_diags = diagnostics.by_category(DiagnosticCategory::Heap);
        assert_eq!(heap_diags.len(), 3);

        let table_diags = diagnostics.by_category(DiagnosticCategory::Table);
        assert_eq!(table_diags.len(), 1);
    }

    #[test]
    fn test_diagnostic_display() {
        let diag = Diagnostic::new(
            DiagnosticSeverity::Warning,
            DiagnosticCategory::CustomAttribute,
            "Parse failed",
        )
        .with_offset(0x1234)
        .with_token(0x0A000005);

        let display = format!("{}", diag);
        assert!(display.contains("WARN"));
        assert!(display.contains("CustomAttribute"));
        assert!(display.contains("Parse failed"));
        assert!(display.contains("0x00001234"));
        assert!(display.contains("0x0a000005"));
    }
}
