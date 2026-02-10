//! Registry for managing obfuscator implementations.
//!
//! The [`ObfuscatorRegistry`] holds all available obfuscators and provides detection
//! functionality to identify which obfuscator(s) were used on an assembly.

use std::{collections::HashMap, sync::Arc};

use crate::{
    compiler::SsaPass,
    deobfuscation::{detection::DetectionScore, obfuscators::Obfuscator, ConfuserExObfuscator},
    CilObject,
};

/// Registry for managing obfuscator implementations.
///
/// The registry holds all available obfuscators and provides detection
/// functionality to identify which obfuscator(s) were used.
///
/// # Example
///
/// ```rust,ignore
/// use std::sync::Arc;
/// use dotscope::deobfuscation::ObfuscatorRegistry;
///
/// // Create an empty registry
/// let mut registry = ObfuscatorRegistry::new();
///
/// // Register custom obfuscators
/// registry.register(Arc::new(MyObfuscator::new()));
/// ```
pub struct ObfuscatorRegistry {
    /// Registered obfuscators.
    obfuscators: HashMap<String, Arc<dyn Obfuscator>>,
    /// Detection threshold (default: 50).
    threshold: usize,
}

impl Default for ObfuscatorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ObfuscatorRegistry {
    /// Creates a new obfuscator registry with all built-in obfuscators registered.
    ///
    /// # Returns
    ///
    /// A new `ObfuscatorRegistry` with built-in obfuscators and a default threshold of 50.
    #[must_use]
    pub fn new() -> Self {
        let mut obfuscators = HashMap::new();

        let confuser: Arc<dyn Obfuscator> = Arc::new(ConfuserExObfuscator::new());
        obfuscators.insert(confuser.name(), confuser);

        Self {
            obfuscators,
            threshold: 50,
        }
    }

    /// Creates a new empty obfuscator registry without any pre-registered obfuscators.
    ///
    /// This is useful for testing or when you want full control over which obfuscators
    /// are registered.
    ///
    /// # Returns
    ///
    /// A new empty `ObfuscatorRegistry` with a default threshold of 50.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            obfuscators: HashMap::new(),
            threshold: 50,
        }
    }

    /// Sets the detection threshold.
    ///
    /// Obfuscators must score at or above this threshold to be considered detected.
    ///
    /// # Arguments
    ///
    /// * `threshold` - The minimum score for positive detection.
    pub fn set_threshold(&mut self, threshold: usize) {
        self.threshold = threshold;
    }

    /// Returns the current detection threshold.
    ///
    /// # Returns
    ///
    /// The minimum score required for positive detection.
    #[must_use]
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Registers an obfuscator with the registry.
    ///
    /// If an obfuscator with the same ID already exists, it will be replaced.
    ///
    /// # Arguments
    ///
    /// * `obfuscator` - The obfuscator implementation to register.
    pub fn register(&mut self, obfuscator: Arc<dyn Obfuscator>) {
        self.obfuscators.insert(obfuscator.id().clone(), obfuscator);
    }

    /// Unregisters an obfuscator by its ID.
    ///
    /// # Arguments
    ///
    /// * `id` - The ID of the obfuscator to remove.
    ///
    /// # Returns
    ///
    /// The removed obfuscator if it existed, `None` otherwise.
    pub fn unregister(&mut self, id: &str) -> Option<Arc<dyn Obfuscator>> {
        self.obfuscators.remove(id)
    }

    /// Retrieves an obfuscator by its ID.
    ///
    /// # Arguments
    ///
    /// * `id` - The ID of the obfuscator to retrieve.
    ///
    /// # Returns
    ///
    /// A reference to the obfuscator if found, `None` otherwise.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Arc<dyn Obfuscator>> {
        self.obfuscators.get(id)
    }

    /// Checks if an obfuscator with the given ID is registered.
    ///
    /// # Arguments
    ///
    /// * `id` - The ID to check.
    ///
    /// # Returns
    ///
    /// `true` if an obfuscator with this ID is registered, `false` otherwise.
    #[must_use]
    pub fn has(&self, id: &str) -> bool {
        self.obfuscators.contains_key(id)
    }

    /// Returns the IDs of all registered obfuscators.
    ///
    /// # Returns
    ///
    /// A vector of obfuscator ID strings.
    #[must_use]
    pub fn obfuscator_ids(&self) -> Vec<&str> {
        self.obfuscators.keys().map(String::as_str).collect()
    }

    /// Returns the number of registered obfuscators.
    ///
    /// # Returns
    ///
    /// The count of obfuscators in the registry.
    #[must_use]
    pub fn len(&self) -> usize {
        self.obfuscators.len()
    }

    /// Checks if the registry has no registered obfuscators.
    ///
    /// # Returns
    ///
    /// `true` if no obfuscators are registered, `false` otherwise.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.obfuscators.is_empty()
    }

    /// Returns an iterator over all registered obfuscators.
    ///
    /// # Returns
    ///
    /// An iterator yielding references to the registered obfuscators.
    pub fn iter(&self) -> impl Iterator<Item = &Arc<dyn Obfuscator>> {
        self.obfuscators.values()
    }

    /// Runs detection on an assembly using all registered obfuscators.
    ///
    /// Each obfuscator evaluates the assembly and returns a confidence score.
    /// Only obfuscators scoring at or above the threshold are included.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The assembly to analyze for obfuscation.
    ///
    /// # Returns
    ///
    /// A list of (obfuscator_id, score) pairs sorted by score descending.
    pub fn detect(&self, assembly: &CilObject) -> Vec<(String, DetectionScore)> {
        let mut results: Vec<(String, DetectionScore)> = self
            .obfuscators
            .iter()
            .map(|(id, obfuscator)| (id.clone(), obfuscator.detect(assembly)))
            .filter(|(_, score)| score.score() >= self.threshold)
            .collect();

        results.sort_by(|a, b| b.1.cmp(&a.1));
        results
    }

    /// Detects and returns the best matching obfuscator for an assembly.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The assembly to analyze.
    ///
    /// # Returns
    ///
    /// The obfuscator with the highest score if any scored above threshold, `None` otherwise.
    pub fn detect_best(&self, assembly: &CilObject) -> Option<Arc<dyn Obfuscator>> {
        let results = self.detect(assembly);
        results
            .first()
            .and_then(|(id, _)| self.obfuscators.get(id).cloned())
    }

    /// Returns all passes from all detected obfuscators.
    ///
    /// Passes are returned in detection score order, with the highest scoring
    /// obfuscator's passes first. This ensures obfuscator-specific passes run
    /// before generic ones.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The assembly to analyze.
    ///
    /// # Returns
    ///
    /// A vector of SSA passes from all detected obfuscators.
    pub fn get_passes_for_detected(&self, assembly: &CilObject) -> Vec<Box<dyn SsaPass>> {
        let detected = self.detect(assembly);
        let mut passes = Vec::new();

        for (id, _) in detected {
            if let Some(obfuscator) = self.obfuscators.get(&id) {
                passes.extend(obfuscator.passes());
            }
        }

        passes
    }

    /// Returns information about all registered obfuscators.
    ///
    /// # Returns
    ///
    /// A vector of [`ObfuscatorInfo`] structs describing each registered obfuscator.
    #[must_use]
    pub fn obfuscator_info(&self) -> Vec<ObfuscatorInfo> {
        self.obfuscators
            .values()
            .map(|o| ObfuscatorInfo {
                id: o.id().clone(),
                name: o.name().clone(),
                description: o.description().to_string(),
                versions: o
                    .supported_versions()
                    .iter()
                    .map(|s| (*s).to_string())
                    .collect(),
            })
            .collect()
    }
}

/// Information about a registered obfuscator.
#[derive(Debug, Clone)]
pub struct ObfuscatorInfo {
    /// Obfuscator ID.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Supported versions.
    pub versions: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestObfuscator {
        id: String,
        score: usize,
    }

    impl TestObfuscator {
        fn new(id: impl ToString, score: usize) -> Self {
            Self {
                id: id.to_string(),
                score,
            }
        }
    }

    impl Obfuscator for TestObfuscator {
        fn id(&self) -> String {
            self.id.clone()
        }

        fn name(&self) -> String {
            self.id.clone()
        }

        fn detect(&self, _assembly: &CilObject) -> DetectionScore {
            DetectionScore::with_score(self.score)
        }
    }

    #[test]
    fn test_registry_basic() {
        let mut registry = ObfuscatorRegistry::empty();
        assert!(registry.is_empty());

        registry.register(Arc::new(TestObfuscator::new("test1", 60)));
        assert!(!registry.is_empty());
        assert_eq!(registry.len(), 1);
        assert!(registry.has("test1"));
        assert!(!registry.has("test2"));
    }

    #[test]
    fn test_registry_threshold_setting() {
        let mut registry = ObfuscatorRegistry::empty();
        assert_eq!(registry.threshold, 50); // default

        registry.set_threshold(30);
        assert_eq!(registry.threshold, 30);
    }

    #[test]
    fn test_registry_get_obfuscator() {
        let mut registry = ObfuscatorRegistry::empty();
        registry.register(Arc::new(TestObfuscator::new("test1", 60)));

        assert!(registry.get("test1").is_some());
        assert!(registry.get("nonexistent").is_none());
    }

    #[test]
    fn test_registry_iter() {
        let mut registry = ObfuscatorRegistry::empty();
        registry.register(Arc::new(TestObfuscator::new("a", 10)));
        registry.register(Arc::new(TestObfuscator::new("b", 20)));

        let ids: Vec<_> = registry.iter().map(|o| o.id()).collect();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&"a".to_string()));
        assert!(ids.contains(&"b".to_string()));
    }

    #[test]
    fn test_registry_unregister() {
        let mut registry = ObfuscatorRegistry::empty();
        registry.register(Arc::new(TestObfuscator::new("test1", 60)));
        assert!(registry.has("test1"));

        let removed = registry.unregister("test1");
        assert!(removed.is_some());
        assert!(!registry.has("test1"));

        let removed_again = registry.unregister("test1");
        assert!(removed_again.is_none());
    }

    #[test]
    fn test_registry_obfuscator_ids() {
        let mut registry = ObfuscatorRegistry::empty();
        registry.register(Arc::new(TestObfuscator::new("a", 10)));
        registry.register(Arc::new(TestObfuscator::new("b", 20)));

        let ids = registry.obfuscator_ids();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&"a"));
        assert!(ids.contains(&"b"));
    }

    #[test]
    fn test_obfuscator_info() {
        let mut registry = ObfuscatorRegistry::empty();
        registry.register(Arc::new(TestObfuscator::new("test1", 60)));

        let info = registry.obfuscator_info();
        assert_eq!(info.len(), 1);
        assert_eq!(info[0].id, "test1");
    }

    #[test]
    fn test_registry_new_has_builtin_obfuscators() {
        let registry = ObfuscatorRegistry::new();
        assert!(!registry.is_empty());
        assert!(registry.has("ConfuserEx"));
    }
}
