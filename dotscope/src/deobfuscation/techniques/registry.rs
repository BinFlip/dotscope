//! Technique registry for managing available deobfuscation techniques.

use std::collections::{HashMap, HashSet};

use crate::deobfuscation::techniques::{
    bitmono::{
        BitMonoAntiDebug, BitMonoCalli, BitMonoHooks, BitMonoJunk, BitMonoNops, BitMonoPeRepair,
        BitMonoRenamer, BitMonoStrings, BitMonoUnmanaged,
    },
    confuserex::{
        ConfuserExAntiDebug, ConfuserExAntiDump, ConfuserExAntiTamper, ConfuserExConstants,
        ConfuserExMarker, ConfuserExMetadata, ConfuserExNativeHelpers, ConfuserExReferenceProxy,
        ConfuserExResources,
    },
    generic::{
        GenericAntiDebug, GenericAntiDump, GenericConstants, GenericDecompiler,
        GenericDelegateProxy, GenericFlattening, GenericHandlers, GenericIldasm, GenericMetadata,
        GenericOpaquePredicates, GenericStrings,
    },
    obfuscar::ObfuscarStrings,
    AttributionResult, Detections, Technique,
};

/// Defines the set of techniques required to attribute an obfuscator.
///
/// An obfuscator is attributed when every technique listed in `required` is
/// detected. The `supporting` list contains additional techniques that
/// strengthen the match and are used for ranking when multiple obfuscators
/// could be attributed.
pub struct ObfuscatorSignature {
    /// Obfuscator name returned in [`AttributionResult`].
    pub name: &'static str,
    /// Technique IDs that must **all** be detected for attribution.
    pub required: &'static [&'static str],
    /// Technique IDs that boost ranking when also detected.
    pub supporting: &'static [&'static str],
}

/// Registry of all available deobfuscation techniques.
///
/// All techniques are stored in a single list regardless of whether they
/// perform byte transforms, SSA passes, or both. The registry provides
/// topological sorting for execution order based on `requires()` and
/// `supersedes()` declarations.
///
/// The registry also holds [`ObfuscatorSignature`] entries that define
/// which combination of techniques uniquely identifies each obfuscator.
pub struct TechniqueRegistry {
    techniques: Vec<Box<dyn Technique>>,
    signatures: Vec<ObfuscatorSignature>,
}

impl TechniqueRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            techniques: Vec::new(),
            signatures: Vec::new(),
        }
    }

    /// Creates a registry pre-populated with all built-in techniques.
    ///
    /// # Byte-capable techniques (12)
    ///
    /// Generic:     metadata, ildasm, handlers, decompiler
    /// ConfuserEx:  marker, metadata, tamper, resources, natives
    /// BitMono:     pe, hooks, junk
    ///
    /// # SSA-capable techniques (18)
    ///
    /// Generic:     flattening, strings, constants, debug, dump, opaquefields, delegates
    /// ConfuserEx:  constants, proxy, debug, dump
    /// BitMono:     calli, strings, unmanaged, debug, nops, renamer
    /// Obfuscar:    strings
    #[must_use]
    pub fn with_defaults() -> Self {
        let mut registry = Self::new();

        // === Generic techniques ===
        registry.register(Box::new(GenericMetadata));
        registry.register(Box::new(GenericIldasm));
        registry.register(Box::new(GenericHandlers));
        registry.register(Box::new(GenericDecompiler));
        registry.register(Box::new(GenericFlattening));
        registry.register(Box::new(GenericStrings));
        registry.register(Box::new(GenericConstants));
        registry.register(Box::new(GenericAntiDebug));
        registry.register(Box::new(GenericAntiDump));
        registry.register(Box::new(GenericOpaquePredicates));
        registry.register(Box::new(GenericDelegateProxy));

        // === ConfuserEx techniques ===
        registry.register(Box::new(ConfuserExMarker));
        registry.register(Box::new(ConfuserExMetadata));
        registry.register(Box::new(ConfuserExAntiTamper));
        registry.register(Box::new(ConfuserExResources));
        registry.register(Box::new(ConfuserExNativeHelpers));
        registry.register(Box::new(ConfuserExConstants));
        registry.register(Box::new(ConfuserExReferenceProxy));
        registry.register(Box::new(ConfuserExAntiDebug));
        registry.register(Box::new(ConfuserExAntiDump));

        // === BitMono techniques ===
        registry.register(Box::new(BitMonoPeRepair));
        registry.register(Box::new(BitMonoHooks));
        registry.register(Box::new(BitMonoJunk));
        registry.register(Box::new(BitMonoCalli));
        registry.register(Box::new(BitMonoStrings));
        registry.register(Box::new(BitMonoUnmanaged));
        registry.register(Box::new(BitMonoAntiDebug));
        registry.register(Box::new(BitMonoNops));
        registry.register(Box::new(BitMonoRenamer));

        // === Obfuscar techniques ===
        registry.register(Box::new(ObfuscarStrings));

        // === Obfuscator signatures ===
        //
        // ConfuserEx: definitive signal is the marker attribute it stamps on every
        // protected assembly. All other techniques add supporting evidence.
        registry.signatures.push(ObfuscatorSignature {
            name: "ConfuserEx",
            required: &["confuserex.marker"],
            supporting: &[
                "confuserex.constants",
                "confuserex.proxy",
                "confuserex.debug",
                "confuserex.dump",
                "confuserex.tamper",
                "confuserex.resources",
                "confuserex.metadata",
                "confuserex.natives",
            ],
        });

        // BitMono: space-containing names (FullRenamer) combined with the br.s
        // junk prefix (BitMethodDotnet) are together highly specific to BitMono.
        registry.signatures.push(ObfuscatorSignature {
            name: "BitMono",
            required: &["bitmono.renamer", "bitmono.junk"],
            supporting: &[
                "bitmono.strings",
                "bitmono.calli",
                "bitmono.debug",
                "bitmono.hooks",
                "bitmono.nops",
                "bitmono.unmanaged",
                "bitmono.pe",
            ],
        });

        // BitMono IL-level: each individual IL technique is specific enough to
        // BitMono's protection suite that detecting any one of them is sufficient
        // for attribution.  These fire on single-protection samples where the
        // high-confidence renamer+junk or pe signatures cannot match.
        //
        // Supporting lists are intentionally symmetric so that the sorting step
        // always promotes the signature with the most corroborating evidence.
        registry.signatures.push(ObfuscatorSignature {
            name: "BitMono",
            required: &["bitmono.strings"],
            supporting: &[
                "bitmono.calli",
                "bitmono.debug",
                "bitmono.hooks",
                "bitmono.nops",
                "bitmono.unmanaged",
                "bitmono.junk",
                "bitmono.renamer",
                "bitmono.pe",
            ],
        });
        registry.signatures.push(ObfuscatorSignature {
            name: "BitMono",
            required: &["bitmono.calli"],
            supporting: &[
                "bitmono.strings",
                "bitmono.debug",
                "bitmono.hooks",
                "bitmono.nops",
                "bitmono.unmanaged",
                "bitmono.junk",
                "bitmono.renamer",
                "bitmono.pe",
            ],
        });
        registry.signatures.push(ObfuscatorSignature {
            name: "BitMono",
            required: &["bitmono.hooks"],
            supporting: &[
                "bitmono.strings",
                "bitmono.calli",
                "bitmono.debug",
                "bitmono.nops",
                "bitmono.unmanaged",
                "bitmono.junk",
                "bitmono.renamer",
                "bitmono.pe",
            ],
        });
        registry.signatures.push(ObfuscatorSignature {
            name: "BitMono",
            required: &["bitmono.unmanaged"],
            supporting: &[
                "bitmono.strings",
                "bitmono.calli",
                "bitmono.debug",
                "bitmono.hooks",
                "bitmono.nops",
                "bitmono.junk",
                "bitmono.renamer",
                "bitmono.pe",
            ],
        });
        registry.signatures.push(ObfuscatorSignature {
            name: "BitMono",
            required: &["bitmono.debug"],
            supporting: &[
                "bitmono.strings",
                "bitmono.calli",
                "bitmono.hooks",
                "bitmono.nops",
                "bitmono.unmanaged",
                "bitmono.junk",
                "bitmono.renamer",
                "bitmono.pe",
            ],
        });
        registry.signatures.push(ObfuscatorSignature {
            name: "BitMono",
            required: &["bitmono.junk"],
            supporting: &[
                "bitmono.strings",
                "bitmono.calli",
                "bitmono.debug",
                "bitmono.hooks",
                "bitmono.nops",
                "bitmono.unmanaged",
                "bitmono.renamer",
                "bitmono.pe",
            ],
        });
        registry.signatures.push(ObfuscatorSignature {
            name: "BitMono",
            required: &["bitmono.nops"],
            supporting: &[
                "bitmono.strings",
                "bitmono.calli",
                "bitmono.debug",
                "bitmono.hooks",
                "bitmono.unmanaged",
                "bitmono.junk",
                "bitmono.renamer",
                "bitmono.pe",
            ],
        });

        // BitMono PE-level: the PE corruption patterns (BitDotNet, BitDecompiler,
        // Packer) are unique to BitMono and sufficient for attribution on their own,
        // even when IL-level protections such as FullRenamer or BitMethodDotnet
        // are absent.  The PE repairs are detected before byte transforms consume
        // them, so this signature fires even after the headers have been repaired.
        registry.signatures.push(ObfuscatorSignature {
            name: "BitMono",
            required: &["bitmono.pe"],
            supporting: &[
                "bitmono.renamer",
                "bitmono.junk",
                "bitmono.strings",
                "bitmono.calli",
                "bitmono.debug",
                "bitmono.hooks",
                "bitmono.nops",
                "bitmono.unmanaged",
            ],
        });

        // Obfuscar: custom string decryption scheme is the primary identifier.
        registry.signatures.push(ObfuscatorSignature {
            name: "Obfuscar",
            required: &["obfuscar.strings"],
            supporting: &[],
        });

        registry
    }

    /// Registers a technique.
    ///
    /// # Arguments
    ///
    /// * `technique` - Boxed [`Technique`] implementation to register.
    pub fn register(&mut self, technique: Box<dyn Technique>) {
        self.techniques.push(technique);
    }

    /// Returns all registered techniques.
    ///
    /// # Returns
    ///
    /// A slice of all techniques in registration order.
    #[must_use]
    pub fn techniques(&self) -> &[Box<dyn Technique>] {
        &self.techniques
    }

    /// Returns `true` if any techniques are registered.
    #[must_use]
    pub fn has_techniques(&self) -> bool {
        !self.techniques.is_empty()
    }

    /// Computes obfuscator attribution from technique detections.
    ///
    /// For each registered [`ObfuscatorSignature`], checks whether all
    /// `required` techniques are detected. Fully matched signatures are
    /// collected and sorted by the number of `supporting` techniques also
    /// detected (descending). The best match is returned.
    ///
    /// Returns `None` if no signature's required techniques are all detected.
    #[must_use]
    pub fn compute_attribution(&self, detections: &Detections) -> Option<AttributionResult> {
        let mut candidates: Vec<AttributionResult> = self
            .signatures
            .iter()
            .filter(|sig| sig.required.iter().all(|id| detections.is_detected(id)))
            .map(|sig| {
                let supporting_matched = sig
                    .supporting
                    .iter()
                    .filter(|id| detections.is_detected(id))
                    .count();

                let mut technique_ids: Vec<String> =
                    sig.required.iter().map(|s| s.to_string()).collect();
                for id in sig.supporting {
                    if detections.is_detected(id) {
                        technique_ids.push(id.to_string());
                    }
                }

                AttributionResult {
                    obfuscator_name: sig.name.to_string(),
                    technique_ids,
                    supporting_matched,
                }
            })
            .collect();

        // Sort: most supporting matches first; break ties by required count (more = stronger).
        candidates.sort_by(|a, b| b.supporting_matched.cmp(&a.supporting_matched));
        candidates.into_iter().next()
    }

    /// Returns attribution results for all detected obfuscators.
    ///
    /// Unlike [`Self::compute_attribution`] which returns only the single best match,
    /// this method returns one entry per unique obfuscator name — the best
    /// matching signature for each name — sorted by `supporting_matched`
    /// descending (most evidence first).
    #[must_use]
    pub fn compute_attributions_all(&self, detections: &Detections) -> Vec<AttributionResult> {
        let mut best_by_name: HashMap<&str, AttributionResult> = HashMap::new();

        for sig in &self.signatures {
            if !sig.required.iter().all(|id| detections.is_detected(id)) {
                continue;
            }

            let supporting_matched = sig
                .supporting
                .iter()
                .filter(|id| detections.is_detected(id))
                .count();

            let mut technique_ids: Vec<String> =
                sig.required.iter().map(|s| s.to_string()).collect();
            for id in sig.supporting {
                if detections.is_detected(id) {
                    technique_ids.push(id.to_string());
                }
            }

            let candidate = AttributionResult {
                obfuscator_name: sig.name.to_string(),
                technique_ids,
                supporting_matched,
            };

            // Keep the best match (most supporting) per obfuscator name.
            match best_by_name.get(sig.name) {
                Some(existing) if existing.supporting_matched >= supporting_matched => {}
                _ => {
                    best_by_name.insert(sig.name, candidate);
                }
            }
        }

        let mut result: Vec<AttributionResult> = best_by_name.into_values().collect();
        result.sort_by(|a, b| b.supporting_matched.cmp(&a.supporting_matched));
        result
    }

    /// Returns techniques sorted by dependency order, filtered by supersedes.
    ///
    /// Techniques with `requires()` dependencies are placed after their
    /// dependencies. Techniques superseded by a currently-detected technique
    /// are excluded entirely.
    ///
    /// # Arguments
    ///
    /// * `detections` - Detection results used to determine which techniques
    ///   are active and which are superseded.
    ///
    /// # Returns
    ///
    /// An ordered vec of technique references ready for sequential execution.
    #[must_use]
    pub fn sorted_techniques(&self, detections: &Detections) -> Vec<&dyn Technique> {
        let mut superseded: HashSet<&str> = HashSet::new();
        for tech in &self.techniques {
            if detections.is_detected(tech.id()) {
                for s in tech.supersedes() {
                    superseded.insert(s);
                }
            }
        }

        let mut eligible: Vec<&dyn Technique> = self
            .techniques
            .iter()
            .filter(|t| !superseded.contains(t.id()))
            .map(|t| &**t)
            .collect();

        eligible.sort_by_key(|t| t.requires().len());
        eligible
    }
}

impl Default for TechniqueRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::deobfuscation::techniques::{
        Detection, Detections, ObfuscatorSignature, Technique, TechniqueCategory, TechniqueRegistry,
    };

    /// Minimal mock technique for registry tests.
    struct MockTechnique {
        id: &'static str,
        requires: &'static [&'static str],
        supersedes: &'static [&'static str],
    }

    impl MockTechnique {
        fn new(id: &'static str) -> Self {
            Self {
                id,
                requires: &[],
                supersedes: &[],
            }
        }

        fn with_requires(id: &'static str, requires: &'static [&'static str]) -> Self {
            Self {
                id,
                requires,
                supersedes: &[],
            }
        }

        fn with_supersedes(id: &'static str, supersedes: &'static [&'static str]) -> Self {
            Self {
                id,
                requires: &[],
                supersedes,
            }
        }
    }

    impl Technique for MockTechnique {
        fn id(&self) -> &'static str {
            self.id
        }
        fn name(&self) -> &'static str {
            self.id
        }
        fn category(&self) -> TechniqueCategory {
            TechniqueCategory::Metadata
        }
        fn detect(&self, _assembly: &crate::CilObject) -> Detection {
            Detection::new_empty()
        }
        fn requires(&self) -> &[&'static str] {
            self.requires
        }
        fn supersedes(&self) -> &[&'static str] {
            self.supersedes
        }
    }

    #[test]
    fn test_registry_new_is_empty() {
        let r = TechniqueRegistry::new();
        assert!(!r.has_techniques());
        assert!(r.techniques().is_empty());
    }

    #[test]
    fn test_registry_register_and_retrieve() {
        let mut r = TechniqueRegistry::new();
        r.register(Box::new(MockTechnique::new("test.a")));
        r.register(Box::new(MockTechnique::new("test.b")));

        assert!(r.has_techniques());
        assert_eq!(r.techniques().len(), 2);
        assert_eq!(r.techniques()[0].id(), "test.a");
        assert_eq!(r.techniques()[1].id(), "test.b");
    }

    #[test]
    fn test_with_defaults_has_techniques() {
        let r = TechniqueRegistry::with_defaults();
        assert!(r.has_techniques());
        assert!(r.techniques().len() >= 30);
    }

    #[test]
    fn test_compute_attribution_no_match() {
        let mut r = TechniqueRegistry::new();
        r.register(Box::new(MockTechnique::new("test.a")));
        r.signatures.push(ObfuscatorSignature {
            name: "TestObfuscator",
            required: &["test.a"],
            supporting: &[],
        });

        let ds = Detections::new();
        assert!(r.compute_attribution(&ds).is_none());
    }

    #[test]
    fn test_compute_attribution_required_match() {
        let mut r = TechniqueRegistry::new();
        r.register(Box::new(MockTechnique::new("test.a")));
        r.signatures.push(ObfuscatorSignature {
            name: "TestObfuscator",
            required: &["test.a"],
            supporting: &["test.b"],
        });

        let mut ds = Detections::new();
        ds.insert("test.a", Detection::new_detected(vec![], None));

        let attr = r.compute_attribution(&ds).unwrap();
        assert_eq!(attr.obfuscator_name, "TestObfuscator");
        assert_eq!(attr.supporting_matched, 0);
    }

    #[test]
    fn test_compute_attribution_with_supporting() {
        let mut r = TechniqueRegistry::new();
        r.register(Box::new(MockTechnique::new("test.a")));
        r.register(Box::new(MockTechnique::new("test.b")));
        r.signatures.push(ObfuscatorSignature {
            name: "TestObfuscator",
            required: &["test.a"],
            supporting: &["test.b", "test.c"],
        });

        let mut ds = Detections::new();
        ds.insert("test.a", Detection::new_detected(vec![], None));
        ds.insert("test.b", Detection::new_detected(vec![], None));

        let attr = r.compute_attribution(&ds).unwrap();
        assert_eq!(attr.supporting_matched, 1);
        assert!(attr.technique_ids.contains(&"test.a".to_string()));
        assert!(attr.technique_ids.contains(&"test.b".to_string()));
    }

    #[test]
    fn test_compute_attribution_best_match_wins() {
        let mut r = TechniqueRegistry::new();
        r.signatures.push(ObfuscatorSignature {
            name: "Weak",
            required: &["weak.a"],
            supporting: &[],
        });
        r.signatures.push(ObfuscatorSignature {
            name: "Strong",
            required: &["strong.a"],
            supporting: &["strong.b", "strong.c"],
        });

        let mut ds = Detections::new();
        ds.insert("weak.a", Detection::new_detected(vec![], None));
        ds.insert("strong.a", Detection::new_detected(vec![], None));
        ds.insert("strong.b", Detection::new_detected(vec![], None));
        ds.insert("strong.c", Detection::new_detected(vec![], None));

        let attr = r.compute_attribution(&ds).unwrap();
        assert_eq!(attr.obfuscator_name, "Strong");
        assert_eq!(attr.supporting_matched, 2);
    }

    #[test]
    fn test_compute_attributions_all() {
        let mut r = TechniqueRegistry::new();
        r.signatures.push(ObfuscatorSignature {
            name: "Alpha",
            required: &["alpha.a"],
            supporting: &[],
        });
        r.signatures.push(ObfuscatorSignature {
            name: "Beta",
            required: &["beta.a"],
            supporting: &["beta.b"],
        });

        let mut ds = Detections::new();
        ds.insert("alpha.a", Detection::new_detected(vec![], None));
        ds.insert("beta.a", Detection::new_detected(vec![], None));
        ds.insert("beta.b", Detection::new_detected(vec![], None));

        let attrs = r.compute_attributions_all(&ds);
        assert_eq!(attrs.len(), 2);
        // Beta has more supporting matches, should come first
        assert_eq!(attrs[0].obfuscator_name, "Beta");
        assert_eq!(attrs[1].obfuscator_name, "Alpha");
    }

    #[test]
    fn test_sorted_techniques_dependency_order() {
        let mut r = TechniqueRegistry::new();
        r.register(Box::new(MockTechnique::with_requires("b", &["a"])));
        r.register(Box::new(MockTechnique::new("a")));

        let ds = Detections::new();
        let sorted = r.sorted_techniques(&ds);
        let ids: Vec<&str> = sorted.iter().map(|t| t.id()).collect();
        // "a" has 0 requires, "b" has 1 — so "a" comes first
        assert_eq!(ids, vec!["a", "b"]);
    }

    #[test]
    fn test_sorted_techniques_supersedes_filtering() {
        let mut r = TechniqueRegistry::new();
        r.register(Box::new(MockTechnique::new("old")));
        r.register(Box::new(MockTechnique::with_supersedes("new", &["old"])));

        let mut ds = Detections::new();
        ds.insert("new", Detection::new_detected(vec![], None));

        let sorted = r.sorted_techniques(&ds);
        let ids: Vec<&str> = sorted.iter().map(|t| t.id()).collect();
        // "old" should be excluded because "new" supersedes it and is detected
        assert!(!ids.contains(&"old"));
        assert!(ids.contains(&"new"));
    }

    #[test]
    fn test_sorted_techniques_supersedes_not_detected() {
        let mut r = TechniqueRegistry::new();
        r.register(Box::new(MockTechnique::new("old")));
        r.register(Box::new(MockTechnique::with_supersedes("new", &["old"])));

        let ds = Detections::new(); // nothing detected
        let sorted = r.sorted_techniques(&ds);
        let ids: Vec<&str> = sorted.iter().map(|t| t.id()).collect();
        // Both should be present since "new" is not detected
        assert!(ids.contains(&"old"));
        assert!(ids.contains(&"new"));
    }

    #[test]
    fn test_registry_default() {
        let r = TechniqueRegistry::default();
        assert!(!r.has_techniques());
    }
}
