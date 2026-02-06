//! Obfuscator detection system.
//!
//! The [`ObfuscatorDetector`] runs all registered obfuscators to identify
//! which obfuscator(s) were used on an assembly.

use std::sync::Arc;

use crate::{
    deobfuscation::{
        detection::{DetectionResult, DetectionScore},
        obfuscators::{Obfuscator, ObfuscatorRegistry},
        pass::SsaPass,
    },
    CilObject,
};

/// Detects which obfuscator was used on an assembly.
///
/// The detector maintains a registry of obfuscators and runs their detection
/// logic to identify the obfuscator with the highest confidence score.
///
/// # Example
///
/// ```rust,ignore
/// use dotscope::deobfuscation::ObfuscatorDetector;
///
/// let detector = ObfuscatorDetector::with_defaults();
/// let result = detector.detect(&assembly);
///
/// if let Some(obfuscator) = result.primary() {
///     println!("Detected: {}", obfuscator.name());
/// }
/// ```
pub struct ObfuscatorDetector {
    /// Obfuscator registry.
    registry: ObfuscatorRegistry,
}

impl Default for ObfuscatorDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ObfuscatorDetector {
    /// Creates a new detector with an empty obfuscator registry.
    ///
    /// # Returns
    ///
    /// A new `ObfuscatorDetector` with no registered obfuscators.
    #[must_use]
    pub fn new() -> Self {
        Self {
            registry: ObfuscatorRegistry::new(),
        }
    }

    /// Creates a detector from an existing obfuscator registry.
    ///
    /// # Arguments
    ///
    /// * `registry` - The obfuscator registry to use for detection.
    ///
    /// # Returns
    ///
    /// A new `ObfuscatorDetector` using the provided registry.
    #[must_use]
    pub fn from_registry(registry: ObfuscatorRegistry) -> Self {
        Self { registry }
    }

    /// Returns a reference to the obfuscator registry.
    ///
    /// # Returns
    ///
    /// A reference to the underlying [`ObfuscatorRegistry`].
    #[must_use]
    pub fn registry(&self) -> &ObfuscatorRegistry {
        &self.registry
    }

    /// Returns a mutable reference to the obfuscator registry.
    ///
    /// # Returns
    ///
    /// A mutable reference to the underlying [`ObfuscatorRegistry`].
    pub fn registry_mut(&mut self) -> &mut ObfuscatorRegistry {
        &mut self.registry
    }

    /// Registers an obfuscator with the detector.
    ///
    /// # Arguments
    ///
    /// * `obfuscator` - The obfuscator implementation to register.
    pub fn register(&mut self, obfuscator: Arc<dyn Obfuscator>) {
        self.registry.register(obfuscator);
    }

    /// Sets the detection threshold.
    ///
    /// Obfuscators must score at or above this threshold to be considered detected.
    ///
    /// # Arguments
    ///
    /// * `threshold` - The minimum score for positive detection (typically 0-100).
    pub fn set_threshold(&mut self, threshold: usize) {
        self.registry.set_threshold(threshold);
    }

    /// Returns the current detection threshold.
    ///
    /// # Returns
    ///
    /// The minimum score required for positive detection.
    #[must_use]
    pub fn threshold(&self) -> usize {
        self.registry.threshold()
    }

    /// Runs detection on an assembly using all registered obfuscators.
    ///
    /// Each obfuscator evaluates the assembly and returns a confidence score.
    /// Obfuscators scoring above the threshold are included in the results.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The assembly to analyze for obfuscation.
    ///
    /// # Returns
    ///
    /// A [`DetectionResult`] containing the primary detected obfuscator
    /// and all candidates that scored above the threshold.
    pub fn detect(&self, assembly: &CilObject) -> DetectionResult {
        let threshold = self.registry.threshold();
        let all_detected = self.registry.detect(assembly);
        let primary_obfuscator = all_detected
            .first()
            .and_then(|(id, _)| self.registry.get(id).cloned());

        DetectionResult::new(primary_obfuscator, all_detected, threshold)
    }

    /// Returns the best matching obfuscator for an assembly.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The assembly to analyze.
    ///
    /// # Returns
    ///
    /// The obfuscator with the highest score if any scored above threshold, `None` otherwise.
    pub fn best_obfuscator(&self, assembly: &CilObject) -> Option<Arc<dyn Obfuscator>> {
        self.registry.detect_best(assembly)
    }

    /// Returns deobfuscation passes from all detected obfuscators.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The assembly to analyze.
    ///
    /// # Returns
    ///
    /// A vector of SSA passes provided by obfuscators that detected their patterns.
    pub fn get_passes(&self, assembly: &CilObject) -> Vec<Box<dyn SsaPass>> {
        self.registry.get_passes_for_detected(assembly)
    }

    /// Runs quick detection, returning the first obfuscator above threshold.
    ///
    /// This is faster than full detection when you only need to know
    /// if any obfuscator was detected, as it stops at the first match.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The assembly to analyze.
    ///
    /// # Returns
    ///
    /// The ID of the first detected obfuscator, or `None` if none detected.
    pub fn quick_detect(&self, assembly: &CilObject) -> Option<String> {
        let threshold = self.registry.threshold();

        for id in self.registry.obfuscator_ids() {
            if let Some(obfuscator) = self.registry.get(id) {
                let score = obfuscator.detect(assembly);
                if score.score() >= threshold {
                    return Some(id.to_string());
                }
            }
        }

        None
    }

    /// Returns detection scores for all obfuscators, including those below threshold.
    ///
    /// This is useful for debugging or when you want to see all candidates
    /// regardless of whether they meet the detection threshold.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The assembly to analyze.
    ///
    /// # Returns
    ///
    /// A vector of (obfuscator ID, score) pairs for all registered obfuscators.
    pub fn all_scores(&self, assembly: &CilObject) -> Vec<(String, DetectionScore)> {
        self.registry
            .obfuscator_ids()
            .iter()
            .filter_map(|id| {
                self.registry
                    .get(id)
                    .map(|o| ((*id).to_string(), o.detect(assembly)))
            })
            .collect()
    }
}

/// Builder for creating an [`ObfuscatorDetector`].
///
/// # Example
///
/// ```rust,ignore
/// use std::sync::Arc;
/// use dotscope::deobfuscation::DetectorBuilder;
///
/// let detector = DetectorBuilder::new()
///     .with_obfuscator(Arc::new(MyObfuscator::new()))
///     .threshold(70)
///     .build();
/// ```
pub struct DetectorBuilder {
    obfuscators: Vec<Arc<dyn Obfuscator>>,
    threshold: usize,
}

impl Default for DetectorBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl DetectorBuilder {
    /// Creates a new detector builder with default settings.
    ///
    /// # Returns
    ///
    /// A new `DetectorBuilder` with an empty obfuscator list and threshold of 50.
    #[must_use]
    pub fn new() -> Self {
        Self {
            obfuscators: Vec::new(),
            threshold: 50,
        }
    }

    /// Adds an obfuscator to the builder.
    ///
    /// # Arguments
    ///
    /// * `obfuscator` - The obfuscator implementation to include.
    ///
    /// # Returns
    ///
    /// The builder instance for method chaining.
    #[must_use]
    pub fn with_obfuscator(mut self, obfuscator: Arc<dyn Obfuscator>) -> Self {
        self.obfuscators.push(obfuscator);
        self
    }

    /// Sets the detection threshold.
    ///
    /// # Arguments
    ///
    /// * `threshold` - The minimum score for positive detection.
    ///
    /// # Returns
    ///
    /// The builder instance for method chaining.
    #[must_use]
    pub fn threshold(mut self, threshold: usize) -> Self {
        self.threshold = threshold;
        self
    }

    /// Builds the detector with all configured obfuscators and settings.
    ///
    /// # Returns
    ///
    /// A new [`ObfuscatorDetector`] with all registered obfuscators and the configured threshold.
    #[must_use]
    pub fn build(self) -> ObfuscatorDetector {
        let mut registry = ObfuscatorRegistry::new();
        registry.set_threshold(self.threshold);

        for obfuscator in self.obfuscators {
            registry.register(obfuscator);
        }

        ObfuscatorDetector::from_registry(registry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_creation() {
        let detector = ObfuscatorDetector::new();
        assert!(!detector.registry().is_empty());
        assert!(detector.registry().has("ConfuserEx"));
    }

    #[test]
    fn test_detector_threshold() {
        let mut detector = ObfuscatorDetector::new();
        detector.set_threshold(75);
        assert_eq!(detector.threshold(), 75);
    }

    #[test]
    fn test_detection_result() {
        let result = DetectionResult::empty(50);

        assert!(!result.detected());
        assert!(result.primary().is_none());
    }

    #[test]
    fn test_detection_result_with_candidates() {
        // Test with candidates but no primary obfuscator (no Arc available in unit test)
        let result = DetectionResult::new(
            None,
            vec![("test".to_string(), DetectionScore::with_score(80))],
            50,
        );

        assert!(!result.detected());
        assert!(result.has("test"));
    }
}
