//! Detection types for the technique framework.
//!
//! [`Detection`] captures what a single technique found during its detect phase.
//! [`Detections`] aggregates results across all techniques and tracks which
//! ones have been transformed.

use std::{
    any::Any,
    collections::{HashMap, HashSet},
};

use crate::{cilassembly::CleanupRequest, metadata::token::Token};

/// A piece of evidence supporting a detection.
#[derive(Debug, Clone)]
pub enum Evidence {
    /// A custom attribute was found (e.g. `"ConfusedByAttribute"`).
    Attribute(String),
    /// A bytecode pattern was matched (e.g. `"xor-decrypt loop"`).
    BytecodePattern(String),
    /// A metadata pattern was matched (e.g. `"renamed to <Module>"`).
    MetadataPattern(String),
    /// A type pattern was matched (e.g. `"<PrivateImplementationDetails>"`).
    TypePattern(String),
    /// A managed resource was found (e.g. `"encrypted constants blob"`).
    Resource(String),
    /// A structural property was detected (e.g. `"switch dispatcher with 50+ cases"`).
    Structural(String),
}

/// Result of a single technique's detection phase.
pub struct Detection {
    /// Whether the technique's target pattern was found.
    pub detected: bool,
    /// Evidence items supporting the detection.
    pub evidence: Vec<Evidence>,
    /// Opaque, technique-specific findings (e.g. decryptor tokens, field maps).
    pub findings: Option<Box<dyn Any + Send + Sync>>,
    /// Cleanup contributions from detection (tokens/sections to remove).
    pub cleanup: CleanupRequest,
}

impl Detection {
    /// Creates an empty detection (not detected).
    #[must_use]
    pub fn new_empty() -> Self {
        Self {
            detected: false,
            evidence: Vec::new(),
            findings: None,
            cleanup: CleanupRequest::new(),
        }
    }

    /// Creates a positive detection with evidence and optional findings.
    #[must_use]
    pub fn new_detected(
        evidence: Vec<Evidence>,
        findings: Option<Box<dyn Any + Send + Sync>>,
    ) -> Self {
        Self {
            detected: true,
            evidence,
            findings,
            cleanup: CleanupRequest::new(),
        }
    }

    /// Sets the opaque findings after construction.
    pub fn set_findings(&mut self, findings: Box<dyn Any + Send + Sync>) {
        self.findings = Some(findings);
    }

    /// Downcast the opaque findings to a concrete type.
    #[must_use]
    pub fn findings<T: 'static>(&self) -> Option<&T> {
        self.findings.as_ref()?.downcast_ref::<T>()
    }

    /// Adds method tokens to the cleanup request (builder pattern).
    #[must_use]
    pub fn with_cleanup_methods(mut self, tokens: impl IntoIterator<Item = Token>) -> Self {
        for token in tokens {
            self.cleanup.add_method(token);
        }
        self
    }

    /// Adds type tokens to the cleanup request (builder pattern).
    #[must_use]
    pub fn with_cleanup_types(mut self, tokens: impl IntoIterator<Item = Token>) -> Self {
        for token in tokens {
            self.cleanup.add_type(token);
        }
        self
    }
}

/// Aggregated detection results across all techniques.
pub struct Detections {
    /// Per-technique detection results, keyed by technique ID.
    entries: HashMap<String, Detection>,
    /// Technique IDs that have been successfully transformed.
    transformed: HashSet<String>,
}

impl Detections {
    /// Creates an empty detections container.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            transformed: HashSet::new(),
        }
    }

    /// Inserts a detection result for a technique.
    pub fn insert(&mut self, id: impl Into<String>, detection: Detection) {
        self.entries.insert(id.into(), detection);
    }

    /// Gets the detection result for a technique.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Detection> {
        self.entries.get(id)
    }

    /// Downcast a technique's findings to a concrete type.
    #[must_use]
    pub fn findings<T: 'static>(&self, id: &str) -> Option<&T> {
        self.entries.get(id)?.findings::<T>()
    }

    /// Returns `true` if the technique was detected (present and `detected == true`).
    #[must_use]
    pub fn is_detected(&self, id: &str) -> bool {
        self.entries.get(id).is_some_and(|d| d.detected)
    }

    /// Returns `true` if the technique has been successfully transformed.
    #[must_use]
    pub fn is_transformed(&self, id: &str) -> bool {
        self.transformed.contains(id)
    }

    /// Marks a technique as transformed.
    pub fn mark_transformed(&mut self, id: impl Into<String>) {
        self.transformed.insert(id.into());
    }

    /// Merges a detection result, never downgrading an existing positive detection.
    ///
    /// - New not detected → no change (existing positive detection is preserved).
    /// - New detected, existing detected → augment evidence, update findings/cleanup.
    /// - New detected, existing not detected → replace with new detection.
    /// - New detected, no existing entry → insert.
    ///
    /// Used both for post-transform re-detection (Phase 2.5) and SSA-level
    /// detection (Phase 3.5). In both cases we must not overwrite a positive
    /// detection that resulted from an earlier phase (e.g. a PE-level technique
    /// whose evidence is consumed by its byte transform and is no longer
    /// visible in the clean assembly).
    pub fn merge(&mut self, id: impl Into<String>, detection: Detection) {
        if !detection.detected {
            return;
        }
        let id = id.into();
        match self.entries.get_mut(&id) {
            Some(existing) if existing.detected => {
                existing.evidence.extend(detection.evidence);
                if detection.findings.is_some() {
                    existing.findings = detection.findings;
                }
                existing.cleanup.merge(&detection.cleanup);
            }
            Some(existing) => {
                *existing = detection;
            }
            None => {
                self.entries.insert(id, detection);
            }
        }
    }

    /// Merges all cleanup contributions into a single result.
    #[must_use]
    pub fn merged_cleanup(&self) -> CleanupRequest {
        let mut request = CleanupRequest::new();
        for detection in self.entries.values() {
            if detection.detected {
                request.merge(&detection.cleanup);
            }
        }
        request
    }
}

impl Default for Detections {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for Evidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Evidence::Attribute(s) => write!(f, "Attribute: {s}"),
            Evidence::BytecodePattern(s) => write!(f, "BytecodePattern: {s}"),
            Evidence::MetadataPattern(s) => write!(f, "MetadataPattern: {s}"),
            Evidence::TypePattern(s) => write!(f, "TypePattern: {s}"),
            Evidence::Resource(s) => write!(f, "Resource: {s}"),
            Evidence::Structural(s) => write!(f, "Structural: {s}"),
        }
    }
}

/// Attribution result linking detected techniques to an obfuscator.
///
/// An obfuscator is attributed when all of its required techniques are detected.
/// The `supporting_matched` count indicates how many additional optional
/// techniques were also found — higher counts give stronger attribution.
#[derive(Debug, Clone)]
pub struct AttributionResult {
    /// Name of the attributed obfuscator (e.g. `"ConfuserEx"`).
    pub obfuscator_name: String,
    /// IDs of techniques that contributed to the attribution.
    pub technique_ids: Vec<String>,
    /// Number of supporting (optional) techniques that were also detected.
    pub supporting_matched: usize,
}

#[cfg(test)]
mod tests {
    use crate::deobfuscation::techniques::{Detection, Detections, Evidence};

    #[test]
    fn test_detection_new_empty() {
        let d = Detection::new_empty();
        assert!(!d.detected);
        assert!(d.evidence.is_empty());
        assert!(d.findings.is_none());
    }

    #[test]
    fn test_detection_new_detected() {
        let evidence = vec![Evidence::Attribute("test".into())];
        let d = Detection::new_detected(evidence, None);
        assert!(d.detected);
        assert_eq!(d.evidence.len(), 1);
        assert!(d.findings.is_none());
    }

    #[test]
    fn test_detection_findings_downcast() {
        #[derive(Debug)]
        struct TestFindings {
            count: usize,
        }

        let findings = Box::new(TestFindings { count: 42 });
        let d = Detection::new_detected(
            vec![],
            Some(findings as Box<dyn std::any::Any + Send + Sync>),
        );

        let f = d.findings::<TestFindings>().unwrap();
        assert_eq!(f.count, 42);

        // Wrong type returns None
        assert!(d.findings::<String>().is_none());
    }

    #[test]
    fn test_detection_findings_none_when_no_findings() {
        let d = Detection::new_detected(vec![], None);
        assert!(d.findings::<String>().is_none());
    }

    #[test]
    fn test_detections_insert_and_get() {
        let mut ds = Detections::new();
        ds.insert("test.a", Detection::new_detected(vec![], None));
        ds.insert("test.b", Detection::new_empty());

        assert!(ds.get("test.a").unwrap().detected);
        assert!(!ds.get("test.b").unwrap().detected);
        assert!(ds.get("nonexistent").is_none());
    }

    #[test]
    fn test_detections_is_detected() {
        let mut ds = Detections::new();
        ds.insert("found", Detection::new_detected(vec![], None));
        ds.insert("not_found", Detection::new_empty());

        assert!(ds.is_detected("found"));
        assert!(!ds.is_detected("not_found"));
        assert!(!ds.is_detected("missing"));
    }

    #[test]
    fn test_detections_transformed() {
        let mut ds = Detections::new();
        assert!(!ds.is_transformed("tech.a"));

        ds.mark_transformed("tech.a");
        assert!(ds.is_transformed("tech.a"));
        assert!(!ds.is_transformed("tech.b"));
    }

    #[test]
    fn test_detections_findings_shortcut() {
        #[derive(Debug)]
        struct MyFindings(u32);

        let mut ds = Detections::new();
        let d = Detection::new_detected(
            vec![],
            Some(Box::new(MyFindings(99)) as Box<dyn std::any::Any + Send + Sync>),
        );
        ds.insert("tech", d);

        assert_eq!(ds.findings::<MyFindings>("tech").unwrap().0, 99);
        assert!(ds.findings::<String>("tech").is_none());
        assert!(ds.findings::<MyFindings>("missing").is_none());
    }

    #[test]
    fn test_merge_new_not_detected_preserves_existing() {
        let mut ds = Detections::new();
        ds.insert(
            "tech",
            Detection::new_detected(vec![Evidence::Attribute("original".into())], None),
        );

        // Merging a not-detected result should be a no-op
        ds.merge("tech", Detection::new_empty());

        let d = ds.get("tech").unwrap();
        assert!(d.detected);
        assert_eq!(d.evidence.len(), 1);
    }

    #[test]
    fn test_merge_new_detected_augments_existing() {
        let mut ds = Detections::new();
        ds.insert(
            "tech",
            Detection::new_detected(vec![Evidence::Attribute("first".into())], None),
        );

        ds.merge(
            "tech",
            Detection::new_detected(vec![Evidence::BytecodePattern("second".into())], None),
        );

        let d = ds.get("tech").unwrap();
        assert!(d.detected);
        assert_eq!(d.evidence.len(), 2);
    }

    #[test]
    fn test_merge_new_detected_replaces_not_detected() {
        let mut ds = Detections::new();
        ds.insert("tech", Detection::new_empty());

        ds.merge(
            "tech",
            Detection::new_detected(vec![Evidence::Attribute("found".into())], None),
        );

        let d = ds.get("tech").unwrap();
        assert!(d.detected);
        assert_eq!(d.evidence.len(), 1);
    }

    #[test]
    fn test_merge_inserts_new_entry() {
        let mut ds = Detections::new();
        ds.merge(
            "new_tech",
            Detection::new_detected(vec![Evidence::Resource("blob".into())], None),
        );

        assert!(ds.is_detected("new_tech"));
    }

    #[test]
    fn test_merge_updates_findings_on_augment() {
        #[derive(Debug)]
        struct V1(u32);
        #[derive(Debug)]
        struct V2(u32);

        let mut ds = Detections::new();
        ds.insert(
            "tech",
            Detection::new_detected(
                vec![],
                Some(Box::new(V1(1)) as Box<dyn std::any::Any + Send + Sync>),
            ),
        );

        ds.merge(
            "tech",
            Detection::new_detected(
                vec![],
                Some(Box::new(V2(2)) as Box<dyn std::any::Any + Send + Sync>),
            ),
        );

        // Findings should be updated to V2
        assert!(ds.findings::<V2>("tech").is_some());
    }

    #[test]
    fn test_evidence_display() {
        let e = Evidence::Attribute("test".into());
        assert_eq!(format!("{e}"), "Attribute: test");

        let e = Evidence::BytecodePattern("xor".into());
        assert_eq!(format!("{e}"), "BytecodePattern: xor");
    }

    #[test]
    fn test_detections_default() {
        let ds = Detections::default();
        assert!(!ds.is_detected("anything"));
    }
}
