//! Unified event logging for the SSA compiler pipeline.
//!
//! This module provides a flexible event logging system that captures all
//! activity during SSA compilation - from individual instruction changes to
//! engine-level decisions. Events can be inspected for debugging or safely
//! ignored when not needed.
//!
//! # Architecture
//!
//! The system is built around three main types:
//!
//! - [`Event`] - A single recorded event (change, warning, info, etc.)
//! - [`EventLog`] - Collection of events with query and summary capabilities
//! - [`EventBuilder`] - Fluent API for creating events
//!
//! # Example
//!
//! ```rust,ignore
//! use dotscope::compiler::{EventLog, EventKind};
//!
//! let mut log = EventLog::new();
//!
//! // Record a string decryption
//! log.record(EventKind::StringDecrypted)
//!     .at(method_token, 0x42)
//!     .message("decrypted: \"hello world\"");
//!
//! // Record an engine-level info
//! log.info("Starting pass: ConstantFolding");
//!
//! // Get summary statistics
//! println!("{}", log.summary());
//! ```

use std::{
    collections::{HashMap, HashSet},
    fmt,
    time::Duration,
};

use crate::metadata::token::Token;

/// Categories of events that can be logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventKind {
    /// A string was decrypted and inlined.
    StringDecrypted,
    /// A constant value was decrypted via emulation of a decryptor method.
    ConstantDecrypted,
    /// A constant value was folded/propagated.
    ConstantFolded,
    /// A conditional branch was simplified to unconditional.
    BranchSimplified,
    /// An instruction was removed.
    InstructionRemoved,
    /// A basic block was removed.
    BlockRemoved,
    /// A method call was inlined.
    MethodInlined,
    /// A phi node was simplified.
    PhiSimplified,
    /// An unknown value was resolved to a constant.
    ValueResolved,
    /// A method was marked as dead (unreachable).
    MethodMarkedDead,
    /// Control flow was restructured (e.g., unflattening).
    ControlFlowRestructured,
    /// An opaque predicate was identified and removed.
    OpaquePredicateRemoved,
    /// A copy operation was propagated away.
    CopyPropagated,
    /// An array was decrypted.
    ArrayDecrypted,
    /// An expensive operation was strength-reduced.
    StrengthReduced,
    /// Orphaned variables were removed from the variable table.
    VariablesCompacted,
    /// An encrypted method body was decrypted (anti-tamper).
    MethodBodyDecrypted,
    /// Anti-tamper protection was removed.
    AntiTamperRemoved,
    /// An obfuscation artifact was removed (method, type, metadata).
    ArtifactRemoved,

    /// A method was identified as a string decryptor.
    DecryptorIdentified,
    /// A method was identified as a dispatcher.
    DispatcherIdentified,
    /// A method was identified as pure (no side effects).
    PureMethodIdentified,
    /// A method was identified as an inlining candidate.
    InlineCandidateIdentified,

    /// Obfuscator detection completed.
    DetectionComplete,
    /// An SSA pass started.
    PassStarted,
    /// An SSA pass completed.
    PassCompleted,
    /// Method processing started.
    MethodProcessingStarted,
    /// Method processing completed.
    MethodProcessingCompleted,
    /// Code regeneration completed.
    CodeRegenerated,

    /// Informational message.
    Info,
    /// Warning (something unexpected but recoverable).
    Warning,
    /// Error (something failed).
    Error,
}

impl EventKind {
    /// Returns a human-readable description of this event kind.
    #[must_use]
    pub fn description(&self) -> &'static str {
        match self {
            // Transformations
            Self::StringDecrypted => "string decrypted",
            Self::ConstantDecrypted => "constant decrypted",
            Self::ConstantFolded => "constant folded",
            Self::BranchSimplified => "branch simplified",
            Self::InstructionRemoved => "instruction removed",
            Self::BlockRemoved => "block removed",
            Self::MethodInlined => "method inlined",
            Self::PhiSimplified => "phi simplified",
            Self::ValueResolved => "value resolved",
            Self::MethodMarkedDead => "method marked dead",
            Self::ControlFlowRestructured => "control flow restructured",
            Self::OpaquePredicateRemoved => "opaque predicate removed",
            Self::CopyPropagated => "copy propagated",
            Self::ArrayDecrypted => "array decrypted",
            Self::StrengthReduced => "strength reduced",
            Self::VariablesCompacted => "variables compacted",
            Self::MethodBodyDecrypted => "method body decrypted",
            Self::AntiTamperRemoved => "anti-tamper removed",
            Self::ArtifactRemoved => "artifact removed",
            // Analysis
            Self::DecryptorIdentified => "decryptor identified",
            Self::DispatcherIdentified => "dispatcher identified",
            Self::PureMethodIdentified => "pure method identified",
            Self::InlineCandidateIdentified => "inline candidate identified",
            // Engine
            Self::DetectionComplete => "detection complete",
            Self::PassStarted => "pass started",
            Self::PassCompleted => "pass completed",
            Self::MethodProcessingStarted => "method processing started",
            Self::MethodProcessingCompleted => "method processing completed",
            Self::CodeRegenerated => "code regenerated",
            // Diagnostic
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }

    /// Returns true if this event represents a code transformation.
    #[must_use]
    pub fn is_transformation(&self) -> bool {
        matches!(
            self,
            Self::StringDecrypted
                | Self::ConstantDecrypted
                | Self::ConstantFolded
                | Self::BranchSimplified
                | Self::InstructionRemoved
                | Self::BlockRemoved
                | Self::MethodInlined
                | Self::PhiSimplified
                | Self::ValueResolved
                | Self::MethodMarkedDead
                | Self::ControlFlowRestructured
                | Self::OpaquePredicateRemoved
                | Self::CopyPropagated
                | Self::ArrayDecrypted
                | Self::StrengthReduced
                | Self::VariablesCompacted
                | Self::MethodBodyDecrypted
                | Self::AntiTamperRemoved
                | Self::ArtifactRemoved
        )
    }

    /// Returns true if this is a diagnostic event (info/warning/error/failure).
    #[must_use]
    pub fn is_diagnostic(&self) -> bool {
        matches!(self, Self::Info | Self::Warning | Self::Error)
    }
}

impl fmt::Display for EventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.description())
    }
}

/// A single logged event.
#[derive(Debug, Clone)]
pub struct Event {
    /// The type of event.
    pub kind: EventKind,
    /// The method where the event occurred (if applicable).
    pub method: Option<Token>,
    /// Location within the method (offset or block ID).
    pub location: Option<usize>,
    /// Human-readable description.
    pub message: String,
    /// Associated pass name (if from a pass).
    pub pass: Option<String>,
}

impl Event {
    /// Creates a new event with the given kind and message.
    fn new(kind: EventKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            method: None,
            location: None,
            message: message.into(),
            pass: None,
        }
    }
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.kind, self.message)
    }
}

/// Builder for creating events with a fluent API.
///
/// Created by [`EventLog::record`]. The event is automatically added
/// to the log when the builder is dropped.
///
/// # Example
///
/// ```rust,ignore
/// log.record(EventKind::StringDecrypted)
///     .at(method, 0x42)
///     .message("decrypted: \"hello\"");
/// ```
pub struct EventBuilder<'a> {
    log: &'a EventLog,
    kind: EventKind,
    method: Option<Token>,
    location: Option<usize>,
    message: Option<String>,
    pass: Option<String>,
}

impl<'a> EventBuilder<'a> {
    fn new(log: &'a EventLog, kind: EventKind) -> Self {
        Self {
            log,
            kind,
            method: None,
            location: None,
            message: None,
            pass: None,
        }
    }

    /// Sets the method and location where the event occurred.
    pub fn at(mut self, method: Token, location: usize) -> Self {
        self.method = Some(method);
        self.location = Some(location);
        self
    }

    /// Sets only the method (for method-level events without specific location).
    pub fn method(mut self, method: Token) -> Self {
        self.method = Some(method);
        self
    }

    /// Sets the location (for when method is already set or not applicable).
    pub fn location(mut self, location: usize) -> Self {
        self.location = Some(location);
        self
    }

    /// Sets a custom message describing the event.
    pub fn message(mut self, msg: impl Into<String>) -> Self {
        self.message = Some(msg.into());
        self
    }

    /// Associates this event with a specific pass.
    pub fn pass(mut self, pass_name: impl Into<String>) -> Self {
        self.pass = Some(pass_name.into());
        self
    }
}

impl Drop for EventBuilder<'_> {
    fn drop(&mut self) {
        let message = self
            .message
            .take()
            .unwrap_or_else(|| self.kind.description().to_string());

        let event = Event {
            kind: self.kind,
            method: self.method.take(),
            location: self.location.take(),
            message,
            pass: self.pass.take(),
        };

        self.log.events.push(event);
    }
}

/// Collection of events from deobfuscation.
///
/// Provides methods for recording events, querying them, and generating
/// summaries. Statistics are derived from the events rather than tracked
/// separately.
///
/// This type is thread-safe: events can be appended concurrently from
/// multiple threads using shared references (`&self`).
#[derive(Debug)]
pub struct EventLog {
    events: boxcar::Vec<Event>,
}

impl Default for EventLog {
    fn default() -> Self {
        Self {
            events: boxcar::Vec::new(),
        }
    }
}

impl Clone for EventLog {
    fn clone(&self) -> Self {
        let new_log = Self::new();
        for (_, event) in &self.events {
            new_log.events.push(event.clone());
        }
        new_log
    }
}

impl EventLog {
    /// Creates an empty event log.
    #[must_use]
    pub fn new() -> Self {
        Self {
            events: boxcar::Vec::new(),
        }
    }

    /// Returns true if no events have been logged.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.count() == 0
    }

    /// Returns the total number of events.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.count()
    }

    /// Starts building a new event of the given kind.
    ///
    /// The event is automatically added when the builder is dropped.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// log.record(EventKind::ConstantFolded)
    ///     .at(method, location)
    ///     .message("42 + 0 → 42");
    /// ```
    pub fn record(&self, kind: EventKind) -> EventBuilder<'_> {
        EventBuilder::new(self, kind)
    }

    /// Records an informational message.
    pub fn info(&self, message: impl Into<String>) {
        self.events.push(Event::new(EventKind::Info, message));
    }

    /// Records a warning message.
    pub fn warn(&self, message: impl Into<String>) {
        self.events.push(Event::new(EventKind::Warning, message));
    }

    /// Records an error message.
    pub fn error(&self, message: impl Into<String>) {
        self.events.push(Event::new(EventKind::Error, message));
    }

    /// Merges another event log into this one by reference.
    pub fn merge_ref(&self, other: &EventLog) {
        for (_, event) in &other.events {
            self.events.push(event.clone());
        }
    }

    /// Merges another event log into this one by value.
    pub fn merge(&self, other: &EventLog) {
        for (_, event) in &other.events {
            self.events.push(event.clone());
        }
    }

    /// Returns true if any event of the given kind exists.
    #[must_use]
    pub fn has(&self, kind: EventKind) -> bool {
        self.events.iter().any(|(_, e)| e.kind == kind)
    }

    /// Returns true if any of the given event kinds exist.
    #[must_use]
    pub fn has_any(&self, kinds: &[EventKind]) -> bool {
        self.events.iter().any(|(_, e)| kinds.contains(&e.kind))
    }

    /// Counts events of the given kind.
    #[must_use]
    pub fn count_kind(&self, kind: EventKind) -> usize {
        self.events.iter().filter(|(_, e)| e.kind == kind).count()
    }

    /// Returns an iterator over all events.
    pub fn iter(&self) -> impl Iterator<Item = &Event> {
        self.events.iter().map(|(_, e)| e)
    }

    /// Returns an iterator over events of a specific kind.
    pub fn filter_kind(&self, kind: EventKind) -> impl Iterator<Item = &Event> + '_ {
        self.events
            .iter()
            .filter_map(move |(_, e)| if e.kind == kind { Some(e) } else { None })
    }

    /// Takes ownership of the events by cloning into a new EventLog.
    ///
    /// This is useful when the context is being consumed and you need to
    /// extract the events. Since `boxcar::Vec` is append-only and doesn't
    /// support draining, this creates a clone.
    #[must_use]
    pub fn take(&self) -> EventLog {
        self.clone()
    }

    /// Returns an iterator over events for a specific method.
    pub fn filter_method(&self, method: Token) -> impl Iterator<Item = &Event> + '_ {
        self.events.iter().filter_map(move |(_, e)| {
            if e.method == Some(method) {
                Some(e)
            } else {
                None
            }
        })
    }

    /// Returns an iterator over transformation events only.
    pub fn transformations(&self) -> impl Iterator<Item = &Event> + '_ {
        self.events.iter().filter_map(|(_, e)| {
            if e.kind.is_transformation() {
                Some(e)
            } else {
                None
            }
        })
    }

    /// Returns an iterator over diagnostic events only.
    pub fn diagnostics(&self) -> impl Iterator<Item = &Event> + '_ {
        self.events.iter().filter_map(|(_, e)| {
            if e.kind.is_diagnostic() {
                Some(e)
            } else {
                None
            }
        })
    }

    /// Returns an iterator over warning events.
    pub fn warnings(&self) -> impl Iterator<Item = &Event> + '_ {
        self.filter_kind(EventKind::Warning)
    }

    /// Returns an iterator over error events.
    pub fn errors(&self) -> impl Iterator<Item = &Event> + '_ {
        self.filter_kind(EventKind::Error)
    }

    /// Counts events grouped by kind.
    #[must_use]
    pub fn count_by_kind(&self) -> HashMap<EventKind, usize> {
        let mut counts = HashMap::new();
        for (_, event) in &self.events {
            *counts.entry(event.kind).or_insert(0) += 1;
        }
        counts
    }

    /// Returns the number of transformation events.
    #[must_use]
    pub fn transformation_count(&self) -> usize {
        self.events
            .iter()
            .filter(|(_, e)| e.kind.is_transformation())
            .count()
    }

    /// Returns the number of unique methods with events.
    #[must_use]
    pub fn methods_affected(&self) -> usize {
        self.events
            .iter()
            .filter_map(|(_, e)| e.method)
            .collect::<HashSet<_>>()
            .len()
    }

    /// Generates a human-readable summary of all events.
    #[must_use]
    pub fn summary(&self) -> String {
        if self.is_empty() {
            return "no events".to_string();
        }

        let counts = self.count_by_kind();

        // Only show transformation counts in summary
        let mut parts: Vec<String> = counts
            .iter()
            .filter(|(k, _)| k.is_transformation())
            .map(|(kind, count)| format!("{} {}", count, kind.description()))
            .collect();

        if parts.is_empty() {
            return format!("{} events", self.len());
        }

        parts.sort();
        parts.join(", ")
    }
}

/// Iterator wrapper for EventLog that yields &Event
pub struct EventLogIter<'a> {
    inner: boxcar::Iter<'a, Event>,
}

impl<'a> Iterator for EventLogIter<'a> {
    type Item = &'a Event;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(_, e)| e)
    }
}

impl<'a> IntoIterator for &'a EventLog {
    type Item = &'a Event;
    type IntoIter = EventLogIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        EventLogIter {
            inner: self.events.iter(),
        }
    }
}

impl Extend<Event> for EventLog {
    fn extend<T: IntoIterator<Item = Event>>(&mut self, iter: T) {
        for event in iter {
            self.events.push(event);
        }
    }
}

impl FromIterator<Event> for EventLog {
    fn from_iter<T: IntoIterator<Item = Event>>(iter: T) -> Self {
        let log = Self::new();
        for event in iter {
            log.events.push(event);
        }
        log
    }
}

/// Statistics derived from an EventLog.
///
/// This replaces manual stat tracking - all numbers are computed from events.
#[derive(Debug, Clone, Default)]
pub struct DerivedStats {
    /// Number of methods that had any transformations.
    pub methods_transformed: usize,
    /// Number of strings decrypted.
    pub strings_decrypted: usize,
    /// Number of arrays decrypted.
    pub arrays_decrypted: usize,
    /// Number of constants folded.
    pub constants_folded: usize,
    /// Number of constants decrypted.
    pub constants_decrypted: usize,
    /// Number of instructions removed.
    pub instructions_removed: usize,
    /// Number of blocks removed.
    pub blocks_removed: usize,
    /// Number of branches simplified.
    pub branches_simplified: usize,
    /// Number of opaque predicates removed.
    pub opaque_predicates_removed: usize,
    /// Number of methods inlined.
    pub methods_inlined: usize,
    /// Number of methods marked dead.
    pub methods_marked_dead: usize,
    /// Number of methods with code regenerated.
    pub methods_regenerated: usize,
    /// Number of dispatchers identified/processed.
    pub dispatchers: usize,
    /// Number of string decryptor methods identified.
    pub string_decryptors: usize,
    /// Number of inline candidates identified.
    pub inline_candidates: usize,
    /// Number of pure methods identified.
    pub pure_methods: usize,
    /// Number of artifacts removed (methods, types, metadata).
    pub artifacts_removed: usize,
    /// Number of warnings.
    pub warnings: usize,
    /// Number of errors.
    pub errors: usize,
    /// Number of pass iterations.
    pub iterations: usize,
    /// Processing time.
    pub total_time: Duration,
}

impl DerivedStats {
    /// Computes statistics from an event log.
    #[must_use]
    pub fn from_log(log: &EventLog) -> Self {
        let counts = log.count_by_kind();
        let get = |kind: EventKind| counts.get(&kind).copied().unwrap_or(0);

        Self {
            methods_transformed: log.methods_affected(),
            strings_decrypted: get(EventKind::StringDecrypted),
            arrays_decrypted: get(EventKind::ArrayDecrypted),
            constants_folded: get(EventKind::ConstantFolded),
            constants_decrypted: get(EventKind::ConstantDecrypted),
            instructions_removed: get(EventKind::InstructionRemoved),
            blocks_removed: get(EventKind::BlockRemoved),
            branches_simplified: get(EventKind::BranchSimplified),
            opaque_predicates_removed: get(EventKind::OpaquePredicateRemoved),
            methods_inlined: get(EventKind::MethodInlined),
            methods_marked_dead: get(EventKind::MethodMarkedDead),
            methods_regenerated: get(EventKind::CodeRegenerated),
            dispatchers: get(EventKind::DispatcherIdentified),
            string_decryptors: get(EventKind::DecryptorIdentified),
            inline_candidates: get(EventKind::InlineCandidateIdentified),
            pure_methods: get(EventKind::PureMethodIdentified),
            artifacts_removed: get(EventKind::ArtifactRemoved),
            warnings: get(EventKind::Warning),
            errors: get(EventKind::Error),
            iterations: 0,
            total_time: Duration::ZERO,
        }
    }

    /// Sets the total processing time.
    #[must_use]
    pub fn with_time(mut self, time: Duration) -> Self {
        self.total_time = time;
        self
    }

    /// Sets the number of iterations.
    #[must_use]
    pub fn with_iterations(mut self, iterations: usize) -> Self {
        self.iterations = iterations;
        self
    }

    /// Generates a human-readable summary.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();

        // Methods affected
        if self.methods_transformed > 0 {
            parts.push(format!("{} methods", self.methods_transformed));
        }

        // Decryption stats (grouped)
        if self.strings_decrypted > 0 {
            parts.push(format!("{} strings decrypted", self.strings_decrypted));
        }
        if self.arrays_decrypted > 0 {
            parts.push(format!("{} arrays decrypted", self.arrays_decrypted));
        }
        if self.constants_decrypted > 0 {
            parts.push(format!("{} constants decrypted", self.constants_decrypted));
        }

        // Optimization stats
        if self.constants_folded > 0 {
            parts.push(format!("{} constants folded", self.constants_folded));
        }
        if self.instructions_removed > 0 {
            parts.push(format!(
                "{} instructions removed",
                self.instructions_removed
            ));
        }
        if self.blocks_removed > 0 {
            parts.push(format!("{} blocks removed", self.blocks_removed));
        }
        if self.branches_simplified > 0 {
            parts.push(format!("{} branches simplified", self.branches_simplified));
        }
        if self.methods_inlined > 0 {
            parts.push(format!("{} inlined", self.methods_inlined));
        }
        if self.opaque_predicates_removed > 0 {
            parts.push(format!(
                "{} opaque predicates",
                self.opaque_predicates_removed
            ));
        }

        // Control flow
        if self.dispatchers > 0 {
            parts.push(format!("{} dispatchers", self.dispatchers));
        }

        // Cleanup stats
        if self.methods_marked_dead > 0 {
            parts.push(format!("{} dead methods", self.methods_marked_dead));
        }
        if self.methods_regenerated > 0 {
            parts.push(format!("{} regenerated", self.methods_regenerated));
        }
        if self.artifacts_removed > 0 {
            parts.push(format!("{} artifacts removed", self.artifacts_removed));
        }

        // Diagnostic info - show errors/warnings
        if self.errors > 0 {
            parts.push(format!("{} errors", self.errors));
        }
        if self.warnings > 0 {
            parts.push(format!("{} warnings", self.warnings));
        }

        let stats = if parts.is_empty() {
            "no transformations".to_string()
        } else {
            parts.join(", ")
        };

        if self.total_time.as_millis() > 0 {
            format!(
                "{} in {:?} ({} iterations)",
                stats, self.total_time, self.iterations
            )
        } else {
            stats
        }
    }
}

impl fmt::Display for DerivedStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.summary())
    }
}

/// Truncates a string for display, adding ellipsis if needed.
#[must_use]
pub fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_log() {
        let log = EventLog::new();
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
        assert!(!log.has(EventKind::StringDecrypted));
    }

    #[test]
    fn test_record_event() {
        let log = EventLog::new();
        let method = Token::new(0x06000001);

        log.record(EventKind::StringDecrypted)
            .at(method, 0x10)
            .message("decrypted: \"hello\"");

        assert!(!log.is_empty());
        assert_eq!(log.len(), 1);
        assert!(log.has(EventKind::StringDecrypted));

        let event = log.iter().next().unwrap();
        assert_eq!(event.method, Some(method));
        assert_eq!(event.location, Some(0x10));
        assert_eq!(event.message, "decrypted: \"hello\"");
    }

    #[test]
    fn test_multiple_events() {
        let log = EventLog::new();
        let method = Token::new(0x06000001);

        log.record(EventKind::StringDecrypted)
            .at(method, 0x10)
            .message("first");
        log.record(EventKind::ConstantFolded)
            .at(method, 0x20)
            .message("second");

        assert_eq!(log.len(), 2);
        assert!(log.has(EventKind::StringDecrypted));
        assert!(log.has(EventKind::ConstantFolded));
        assert!(!log.has(EventKind::BlockRemoved));
    }

    #[test]
    fn test_info_warn_error() {
        let log = EventLog::new();

        log.info("informational message");
        log.warn("warning message");
        log.error("error message");

        assert_eq!(log.count_kind(EventKind::Info), 1);
        assert_eq!(log.count_kind(EventKind::Warning), 1);
        assert_eq!(log.count_kind(EventKind::Error), 1);
    }

    #[test]
    fn test_has_any() {
        let log = EventLog::new();
        let method = Token::new(0x06000001);

        log.record(EventKind::StringDecrypted).at(method, 0x10);

        assert!(log.has_any(&[EventKind::StringDecrypted, EventKind::ArrayDecrypted]));
        assert!(!log.has_any(&[EventKind::BlockRemoved, EventKind::MethodInlined]));
    }

    #[test]
    fn test_merge() {
        let log1 = EventLog::new();
        let log2 = EventLog::new();
        let method = Token::new(0x06000001);

        log1.record(EventKind::StringDecrypted).at(method, 0x10);
        log2.record(EventKind::ConstantFolded).at(method, 0x20);

        log1.merge_ref(&log2);

        assert_eq!(log1.len(), 2);
        assert!(log1.has(EventKind::StringDecrypted));
        assert!(log1.has(EventKind::ConstantFolded));
    }

    #[test]
    fn test_summary() {
        let log = EventLog::new();
        let method = Token::new(0x06000001);

        log.record(EventKind::StringDecrypted).at(method, 0x10);
        log.record(EventKind::StringDecrypted).at(method, 0x20);
        log.record(EventKind::ConstantFolded).at(method, 0x30);

        let summary = log.summary();
        assert!(summary.contains("2 string decrypted"));
        assert!(summary.contains("1 constant folded"));
    }

    #[test]
    fn test_count_by_kind() {
        let log = EventLog::new();
        let method = Token::new(0x06000001);

        log.record(EventKind::StringDecrypted).at(method, 0x10);
        log.record(EventKind::StringDecrypted).at(method, 0x20);
        log.record(EventKind::ConstantFolded).at(method, 0x30);

        let counts = log.count_by_kind();
        assert_eq!(counts.get(&EventKind::StringDecrypted), Some(&2));
        assert_eq!(counts.get(&EventKind::ConstantFolded), Some(&1));
        assert_eq!(counts.get(&EventKind::BlockRemoved), None);
    }

    #[test]
    fn test_derived_stats() {
        let log = EventLog::new();
        let method1 = Token::new(0x06000001);
        let method2 = Token::new(0x06000002);

        log.record(EventKind::StringDecrypted).at(method1, 0x10);
        log.record(EventKind::StringDecrypted).at(method2, 0x20);
        log.record(EventKind::ConstantFolded).at(method1, 0x30);
        log.warn("a warning");

        let stats = DerivedStats::from_log(&log);
        assert_eq!(stats.methods_transformed, 2);
        assert_eq!(stats.strings_decrypted, 2);
        assert_eq!(stats.constants_folded, 1);
        assert_eq!(stats.warnings, 1);
    }

    #[test]
    fn test_filter_methods() {
        let log = EventLog::new();
        let method1 = Token::new(0x06000001);
        let method2 = Token::new(0x06000002);

        log.record(EventKind::StringDecrypted).at(method1, 0x10);
        log.record(EventKind::ConstantFolded).at(method2, 0x20);
        log.record(EventKind::BlockRemoved).at(method1, 0x30);

        let method1_events: Vec<_> = log.filter_method(method1).collect();
        assert_eq!(method1_events.len(), 2);
    }

    #[test]
    fn test_transformations_filter() {
        let log = EventLog::new();
        let method = Token::new(0x06000001);

        log.record(EventKind::StringDecrypted).at(method, 0x10);
        log.info("some info");
        log.warn("some warning");
        log.record(EventKind::BlockRemoved).at(method, 0x20);

        let transformations: Vec<_> = log.transformations().collect();
        assert_eq!(transformations.len(), 2);

        let diagnostics: Vec<_> = log.diagnostics().collect();
        assert_eq!(diagnostics.len(), 2);
    }

    #[test]
    fn test_event_with_pass() {
        let log = EventLog::new();
        let method = Token::new(0x06000001);

        log.record(EventKind::ConstantFolded)
            .at(method, 0x10)
            .pass("ConstantFolding")
            .message("42 + 0 → 42");

        let event = log.iter().next().unwrap();
        assert_eq!(event.pass.as_deref(), Some("ConstantFolding"));
    }

    #[test]
    fn test_default_message() {
        let log = EventLog::new();
        let method = Token::new(0x06000001);

        // No explicit message - should use default from kind
        log.record(EventKind::StringDecrypted).at(method, 0x10);

        let event = log.iter().next().unwrap();
        assert_eq!(event.message, "string decrypted");
    }

    #[test]
    fn test_thread_safe_append() {
        use std::sync::Arc;
        use std::thread;

        let log = Arc::new(EventLog::new());
        let mut handles = vec![];

        // Spawn multiple threads that append to the same log
        for i in 0..4 {
            let log_clone = Arc::clone(&log);
            handles.push(thread::spawn(move || {
                for j in 0..100 {
                    let method = Token::new(0x06000000 + (i * 100 + j) as u32);
                    log_clone
                        .record(EventKind::StringDecrypted)
                        .at(method, j)
                        .message(format!("thread {} event {}", i, j));
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // All 400 events should be present
        assert_eq!(log.len(), 400);
    }
}
