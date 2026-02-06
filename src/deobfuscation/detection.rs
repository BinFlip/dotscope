//! Detection scoring and evidence types for obfuscator identification.
//!
//! This module provides types for scoring obfuscator detection confidence
//! and tracking what evidence contributed to the detection.

use std::cmp::Ordering;
use std::fmt;
use std::sync::{
    atomic::{AtomicUsize, Ordering as AtomicOrdering},
    Arc,
};

use crate::{deobfuscation::obfuscators::Obfuscator, metadata::token::Token};

/// Confidence score for obfuscator detection.
///
/// Scores are on a 0-100+ scale:
/// - 0-20: Very low confidence (might be false positive)
/// - 21-50: Low confidence (some indicators present)
/// - 51-75: Medium confidence (multiple indicators)
/// - 76-90: High confidence (strong indicators)
/// - 91-100+: Very high confidence (definitive markers)
pub struct DetectionScore {
    /// Primary score (0-100+, higher = more confident).
    score: AtomicUsize,
    /// Evidence that contributed to this score.
    evidence: boxcar::Vec<DetectionEvidence>,
}

impl DetectionScore {
    /// Creates a new empty detection score with zero confidence.
    ///
    /// # Returns
    ///
    /// A new `DetectionScore` with score 0 and no evidence.
    #[must_use]
    pub fn new() -> Self {
        Self {
            score: AtomicUsize::new(0),
            evidence: boxcar::Vec::new(),
        }
    }

    /// Creates a score with an initial value but no evidence.
    ///
    /// # Arguments
    ///
    /// * `score` - The initial confidence score (0-100+).
    ///
    /// # Returns
    ///
    /// A new `DetectionScore` with the specified score.
    #[must_use]
    pub fn with_score(score: usize) -> Self {
        Self {
            score: AtomicUsize::new(score),
            evidence: boxcar::Vec::new(),
        }
    }

    /// Returns the total confidence score.
    ///
    /// # Returns
    ///
    /// The current score value (0-100+, higher means more confident).
    #[must_use]
    pub fn score(&self) -> usize {
        self.score.load(AtomicOrdering::Relaxed)
    }

    /// Returns an iterator over all evidence that contributed to this score.
    ///
    /// # Returns
    ///
    /// An iterator over detection evidence items.
    pub fn evidence(&self) -> impl Iterator<Item = &DetectionEvidence> {
        (0..self.evidence.count()).filter_map(|i| self.evidence.get(i))
    }

    /// Adds evidence and increases the score by the evidence's confidence value.
    ///
    /// This method is thread-safe and can be called from multiple threads.
    ///
    /// # Arguments
    ///
    /// * `evidence` - The detection evidence to add.
    pub fn add(&self, evidence: DetectionEvidence) {
        self.score
            .fetch_add(evidence.confidence(), AtomicOrdering::Relaxed);
        self.evidence.push(evidence);
    }

    /// Adds evidence without recalculating the score.
    ///
    /// Use this when the score is already set and you only want to record evidence.
    /// This method is thread-safe.
    ///
    /// # Arguments
    ///
    /// * `evidence` - The detection evidence to add.
    pub fn add_evidence(&self, evidence: DetectionEvidence) {
        self.evidence.push(evidence);
    }

    /// Sets the score directly, overriding any calculated value.
    ///
    /// # Arguments
    ///
    /// * `score` - The new score value.
    pub fn set_score(&self, score: usize) {
        self.score.store(score, AtomicOrdering::Relaxed);
    }

    /// Checks if the score meets or exceeds a threshold.
    ///
    /// # Arguments
    ///
    /// * `threshold` - The threshold to compare against.
    ///
    /// # Returns
    ///
    /// `true` if the score is greater than or equal to the threshold.
    #[must_use]
    pub fn meets_threshold(&self, threshold: usize) -> bool {
        self.score() >= threshold
    }

    /// Checks if this is a confident detection (score >= 50).
    ///
    /// # Returns
    ///
    /// `true` if the score indicates medium or higher confidence.
    #[must_use]
    pub fn is_confident(&self) -> bool {
        self.score() >= 50
    }

    /// Checks if this is a high-confidence detection (score >= 75).
    ///
    /// # Returns
    ///
    /// `true` if the score indicates high confidence.
    #[must_use]
    pub fn is_high_confidence(&self) -> bool {
        self.score() >= 75
    }

    /// Merges another detection score into this one.
    ///
    /// Adds the other score's value and appends all its evidence.
    ///
    /// # Arguments
    ///
    /// * `other` - The detection score to merge into this one.
    pub fn merge(&self, other: &DetectionScore) {
        self.score.fetch_add(other.score(), AtomicOrdering::Relaxed);
        for i in 0..other.evidence.count() {
            if let Some(ev) = other.evidence.get(i) {
                self.evidence.push(ev.clone());
            }
        }
    }

    /// Generates a summary string of all evidence.
    ///
    /// # Returns
    ///
    /// A comma-separated string of short evidence descriptions,
    /// or "no evidence" if no evidence has been recorded.
    #[must_use]
    pub fn evidence_summary(&self) -> String {
        if self.evidence.count() == 0 {
            return "no evidence".to_string();
        }

        self.evidence()
            .map(DetectionEvidence::short_description)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

impl Default for DetectionScore {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for DetectionScore {
    fn clone(&self) -> Self {
        let new_score = Self::with_score(self.score());
        for i in 0..self.evidence.count() {
            if let Some(ev) = self.evidence.get(i) {
                new_score.evidence.push(ev.clone());
            }
        }
        new_score
    }
}

impl fmt::Debug for DetectionScore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DetectionScore")
            .field("score", &self.score())
            .field("evidence_count", &self.evidence.count())
            .finish()
    }
}

impl PartialEq for DetectionScore {
    fn eq(&self, other: &Self) -> bool {
        self.score() == other.score()
    }
}

impl Eq for DetectionScore {}

impl PartialOrd for DetectionScore {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DetectionScore {
    fn cmp(&self, other: &Self) -> Ordering {
        self.score().cmp(&other.score())
    }
}

impl fmt::Display for DetectionScore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "score={} ({})", self.score(), self.evidence_summary())
    }
}

/// Evidence that contributed to obfuscator detection.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)] // BytecodePattern stores location data - boxing would add indirection for common case
pub enum DetectionEvidence {
    /// Found a specific custom attribute.
    Attribute {
        /// Attribute name (e.g., "SmartAssembly.Attributes.PoweredByAttribute").
        name: String,
        /// Confidence contribution (typically 10-50).
        confidence: usize,
    },

    /// Found types/methods matching known patterns.
    TypePattern {
        /// Pattern description (e.g., "<Module>*Confuser*").
        pattern: String,
        /// Number of matches found.
        match_count: usize,
        /// Confidence per match (total = confidence * match_count, capped).
        confidence_per_match: usize,
    },

    /// Found specific bytecode patterns.
    BytecodePattern {
        /// Pattern name (e.g., "ConstantDecryption", "ProxyCall").
        name: String,
        /// Locations where pattern was found.
        locations: boxcar::Vec<Token>,
        /// Confidence contribution.
        confidence: usize,
    },

    /// Found resource with specific characteristics.
    Resource {
        /// Resource name or pattern.
        name: String,
        /// First few bytes of content (signature).
        signature: Vec<u8>,
        /// Confidence contribution.
        confidence: usize,
    },

    /// Extracted version information.
    Version {
        /// Obfuscator name.
        obfuscator: String,
        /// Version string.
        version: String,
        /// Confidence contribution.
        confidence: usize,
    },

    /// Found characteristic string in metadata.
    MetadataString {
        /// The string found.
        value: String,
        /// Where it was found.
        location: String,
        /// Confidence contribution.
        confidence: usize,
    },

    /// Found characteristic module/type structure.
    StructuralPattern {
        /// Pattern description.
        description: String,
        /// Confidence contribution.
        confidence: usize,
    },

    /// Negative evidence (reduces confidence).
    Contradiction {
        /// What contradicts.
        description: String,
        /// Confidence reduction (negative contribution).
        confidence_reduction: usize,
    },

    /// Found methods with encrypted bodies.
    EncryptedMethodBodies {
        /// Number of methods with encrypted bodies.
        count: usize,
        /// Confidence contribution.
        confidence: usize,
    },

    /// Found artifact PE sections that will be removed during cleanup.
    ArtifactSections {
        /// Section names identified for removal.
        sections: Vec<String>,
        /// Confidence contribution (low - artifact sections alone aren't definitive).
        confidence: usize,
    },

    /// Found constant data infrastructure (FieldRVA entries for encrypted data).
    ConstantDataFields {
        /// Number of fields with FieldRVA entries used for encrypted constants.
        field_count: usize,
        /// Number of backing value types created for the fields.
        type_count: usize,
        /// Confidence contribution.
        confidence: usize,
    },

    /// Found protection infrastructure (types/methods to be removed during cleanup).
    ProtectionInfrastructure {
        /// Description of what was found.
        description: String,
        /// Number of items (methods, types, etc.).
        count: usize,
        /// Confidence contribution (informational, low confidence).
        confidence: usize,
    },
}

impl DetectionEvidence {
    /// Returns the confidence contribution of this evidence.
    ///
    /// For `TypePattern`, the confidence is calculated as `match_count * confidence_per_match`,
    /// capped at 50 to prevent runaway scoring. For `Contradiction`, returns 0 as the
    /// reduction is handled separately.
    ///
    /// # Returns
    ///
    /// The confidence value this evidence contributes to the detection score.
    #[must_use]
    pub fn confidence(&self) -> usize {
        match self {
            Self::TypePattern {
                match_count,
                confidence_per_match,
                ..
            } => (*match_count * confidence_per_match).min(50), // Cap at 50
            Self::Attribute { confidence, .. }
            | Self::BytecodePattern { confidence, .. }
            | Self::Resource { confidence, .. }
            | Self::Version { confidence, .. }
            | Self::MetadataString { confidence, .. }
            | Self::StructuralPattern { confidence, .. }
            | Self::EncryptedMethodBodies { confidence, .. }
            | Self::ArtifactSections { confidence, .. }
            | Self::ConstantDataFields { confidence, .. }
            | Self::ProtectionInfrastructure { confidence, .. } => *confidence,
            Self::Contradiction {
                confidence_reduction,
                ..
            } => 0_usize.saturating_sub(*confidence_reduction), // Returns 0, score subtracted elsewhere
        }
    }

    /// Generates a short description suitable for summaries.
    ///
    /// # Returns
    ///
    /// A compact string describing this evidence (e.g., "attr:PoweredBy", "version:Test@1.0").
    #[must_use]
    pub fn short_description(&self) -> String {
        match self {
            Self::Attribute { name, .. } => format!("attr:{name}"),
            Self::TypePattern {
                pattern,
                match_count,
                ..
            } => format!("types:{pattern}x{match_count}"),
            Self::BytecodePattern {
                name, locations, ..
            } => {
                format!("bytecode:{}x{}", name, locations.count())
            }
            Self::Resource { name, .. } => format!("resource:{name}"),
            Self::Version {
                obfuscator,
                version,
                ..
            } => format!("version:{obfuscator}@{version}"),
            Self::MetadataString { value, .. } => format!("string:{value}"),
            Self::StructuralPattern { description, .. } => {
                format!("structure:{description}")
            }
            Self::Contradiction { description, .. } => {
                format!("contra:{description}")
            }
            Self::EncryptedMethodBodies { count, .. } => {
                format!("encrypted:{count} methods")
            }
            Self::ArtifactSections { sections, .. } => {
                format!("artifact sections:{}", sections.len())
            }
            Self::ConstantDataFields {
                field_count,
                type_count,
                ..
            } => {
                format!("constant data:{field_count} fields, {type_count} types")
            }
            Self::ProtectionInfrastructure {
                description, count, ..
            } => {
                format!("{description}:{count}")
            }
        }
    }
}

/// Result of running obfuscator detection.
#[derive(Clone, Default)]
pub struct DetectionResult {
    /// Reference to the primary obfuscator implementation (highest score above threshold).
    primary_obfuscator: Option<Arc<dyn Obfuscator>>,

    /// All detected obfuscators with their scores, sorted by score descending.
    all_detected: Vec<(String, DetectionScore)>,

    /// The detection threshold that was used.
    threshold: usize,
}

impl DetectionResult {
    /// Creates a new empty detection result with the specified threshold.
    ///
    /// # Arguments
    ///
    /// * `threshold` - The minimum score required for an obfuscator to be considered detected.
    ///
    /// # Returns
    ///
    /// A new `DetectionResult` with no detected obfuscators.
    #[must_use]
    pub fn empty(threshold: usize) -> Self {
        Self {
            primary_obfuscator: None,
            all_detected: Vec::new(),
            threshold,
        }
    }

    /// Creates a detection result with all fields.
    ///
    /// # Arguments
    ///
    /// * `primary_obfuscator` - Reference to the primary obfuscator implementation.
    /// * `all_detected` - All detected obfuscators with their scores.
    /// * `threshold` - The detection threshold that was used.
    ///
    /// # Returns
    ///
    /// A new `DetectionResult` with the specified values.
    #[must_use]
    pub fn new(
        primary_obfuscator: Option<Arc<dyn Obfuscator>>,
        all_detected: Vec<(String, DetectionScore)>,
        threshold: usize,
    ) -> Self {
        Self {
            primary_obfuscator,
            all_detected,
            threshold,
        }
    }

    /// Checks if any obfuscator was detected above the threshold.
    ///
    /// # Returns
    ///
    /// `true` if a primary obfuscator was identified, `false` otherwise.
    #[must_use]
    pub fn detected(&self) -> bool {
        self.primary_obfuscator.is_some()
    }

    /// Returns the primary obfuscator implementation (highest score above threshold).
    ///
    /// This provides direct access to the detected obfuscator. Use `.id()` or `.name()`
    /// on the returned obfuscator to get identification info.
    ///
    /// # Returns
    ///
    /// A reference to the obfuscator Arc if one was detected, `None` otherwise.
    #[must_use]
    pub fn primary(&self) -> Option<&Arc<dyn Obfuscator>> {
        self.primary_obfuscator.as_ref()
    }

    /// Returns the detection threshold that was used.
    ///
    /// # Returns
    ///
    /// The minimum score required for detection.
    #[must_use]
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Returns all detected obfuscators with their scores.
    ///
    /// # Returns
    ///
    /// A slice of (obfuscator ID, score) pairs, sorted by score descending.
    #[must_use]
    pub fn all(&self) -> &[(String, DetectionScore)] {
        &self.all_detected
    }

    /// Checks if a specific obfuscator was detected.
    ///
    /// # Arguments
    ///
    /// * `obfuscator_id` - The ID of the obfuscator to check.
    ///
    /// # Returns
    ///
    /// `true` if the obfuscator is in the detected list, `false` otherwise.
    #[must_use]
    pub fn has(&self, obfuscator_id: &str) -> bool {
        self.all_detected.iter().any(|(id, _)| id == obfuscator_id)
    }

    /// Generates a human-readable summary of the detection results.
    ///
    /// # Returns
    ///
    /// A formatted string describing the primary detection and candidate count.
    #[must_use]
    pub fn summary(&self) -> String {
        if let Some(obfuscator) = &self.primary_obfuscator {
            let name = obfuscator.name();
            let score = self
                .all_detected
                .iter()
                .find(|(oname, _)| *oname == name)
                .map_or(0, |(_, s)| s.score());
            format!(
                "Detected: {} (score={}), {} total candidates",
                obfuscator.name(),
                score,
                self.all_detected.len()
            )
        } else {
            "No obfuscator detected".to_string()
        }
    }
}

impl fmt::Display for DetectionResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary())
    }
}

impl fmt::Debug for DetectionResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DetectionResult")
            .field(
                "primary",
                &self.primary_obfuscator.as_ref().map(|o| o.name()),
            )
            .field("all_detected", &self.all_detected)
            .field("threshold", &self.threshold)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detection_score_basic() {
        let score = DetectionScore::new();
        assert_eq!(score.score(), 0);
        assert!(!score.is_confident());

        score.add(DetectionEvidence::Attribute {
            name: "TestAttribute".to_string(),
            confidence: 30,
        });

        assert_eq!(score.score(), 30);
        assert!(!score.is_confident());

        score.add(DetectionEvidence::TypePattern {
            pattern: "*Test*".to_string(),
            match_count: 3,
            confidence_per_match: 10,
        });

        assert_eq!(score.score(), 60); // 30 + min(30, 50)
        assert!(score.is_confident());
    }

    #[test]
    fn test_detection_score_comparison() {
        let score1 = DetectionScore::with_score(50);
        let score2 = DetectionScore::with_score(75);
        let score3 = DetectionScore::with_score(50);

        assert!(score2 > score1);
        assert!(score1 < score2);
        assert_eq!(score1, score3);
    }

    #[test]
    fn test_type_pattern_cap() {
        let score = DetectionScore::new();
        score.add(DetectionEvidence::TypePattern {
            pattern: "*".to_string(),
            match_count: 100,
            confidence_per_match: 10,
        });

        // Should be capped at 50
        assert_eq!(score.score(), 50);
    }

    #[test]
    fn test_detection_result() {
        // Test without primary obfuscator (just the all_detected list)
        let result = DetectionResult::new(
            None,
            vec![
                ("confuserex".to_string(), DetectionScore::with_score(80)),
                ("dotfuscator".to_string(), DetectionScore::with_score(30)),
            ],
            50,
        );

        assert!(!result.detected());
        assert!(result.primary().is_none());
        assert!(result.has("confuserex"));
        assert!(result.has("dotfuscator"));
        assert!(!result.has("unknown"));
    }

    #[test]
    fn test_evidence_summary() {
        let score = DetectionScore::new();
        score.add(DetectionEvidence::Attribute {
            name: "PoweredBy".to_string(),
            confidence: 20,
        });
        score.add(DetectionEvidence::Version {
            obfuscator: "Test".to_string(),
            version: "1.0".to_string(),
            confidence: 30,
        });

        let summary = score.evidence_summary();
        assert!(summary.contains("attr:PoweredBy"));
        assert!(summary.contains("version:Test@1.0"));
    }
}
