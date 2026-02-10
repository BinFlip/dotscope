//! Protection candidate detection and scoring.
//!
//! This module provides utilities for finding and ranking protection initializer
//! methods in ConfuserEx-protected assemblies. Rather than using simple heuristics
//! like "smallest method", we use call graph analysis and pattern scoring to
//! identify the most likely candidates.
//!
//! # Architecture
//!
//! The detection process follows these steps:
//!
//! 1. **Find `.cctor`** — locate the `<Module>` type's static constructor
//! 2. **Extract callees** — find all methods called directly from `.cctor` (+10 base score)
//! 3. **Score candidates** — apply protection-specific scoring rules (see below)
//! 4. **Rank and select** — sort by score descending, discard zero-score entries
//! 5. **Global fallback** — if no `.cctor` callees match, scan all methods in the assembly
//!
//! # Scoring Rules
//!
//! Each protection type is scored by scanning the candidate method's call targets
//! (via `call`, `callvirt`, `newobj`) and matching against known API patterns:
//!
//! ## Anti-Tamper
//!
//! Anti-tamper initializers manipulate PE memory to decrypt method bodies at runtime:
//! - `GetHINSTANCE` / `VirtualProtect` — PE memory manipulation (+5 each)
//! - `get_Module` / `GetModuleHandle` — module handle access (+3)
//! - `GetMethod` / `MethodBase` — reflection on methods (+2)
//! - `Invoke` — dynamic method invocation (+2)
//!
//! ## Resources
//!
//! Resource initializers register assembly resolution hooks and embed encrypted data:
//! - `add_AssemblyResolve` / `add_ResourceResolve` — event handler registration (+5 each)
//! - `Assembly.Load` — dynamic assembly loading (+5)
//! - `Decompress` / `Lzma` / `Inflate` — decompression routines (+3)
//! - `InitializeArray` — embedded data via `RuntimeHelpers` (+3)
//! - Event delegate creation via `newobj` (+2), static field access (+1)
//!
//! ## Constants
//!
//! Constants initializers prepare decryption buffers for encrypted values:
//! - `BlockCopy` / `Buffer` — buffer operations (+3)
//! - `BitConverter` — byte-to-value conversion (+2)
//! - `Array.GetValue` — array indexing (+2)
//! - Static field access (+2)

use crate::{
    assembly::Operand,
    metadata::{tables::TableId, token::Token},
    CilObject,
};

/// CIL opcode for `call` instruction.
const OPCODE_CALL: u8 = 0x28;
/// CIL opcode for `callvirt` instruction.
const OPCODE_CALLVIRT: u8 = 0x6F;
/// CIL opcode for `newobj` instruction.
const OPCODE_NEWOBJ: u8 = 0x73;

/// Type of protection to detect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionType {
    /// Anti-tamper protection (encrypted method bodies).
    AntiTamper,
    /// Resource protection (encrypted embedded resources).
    Resources,
    /// Constants protection (encrypted constant values).
    Constants,
}

/// A candidate protection initializer with confidence score.
#[derive(Debug, Clone)]
pub struct ProtectionCandidate {
    /// The method token of this candidate.
    pub token: Token,
    /// Confidence score (higher = more likely).
    pub score: u32,
    /// Human-readable reasons for the score.
    pub reasons: Vec<&'static str>,
    /// Whether this method is called directly from .cctor.
    pub called_from_cctor: bool,
}

impl ProtectionCandidate {
    /// Creates a new candidate with zero score.
    fn new(token: Token) -> Self {
        Self {
            token,
            score: 0,
            reasons: Vec::new(),
            called_from_cctor: false,
        }
    }

    /// Adds points with a reason.
    fn add_score(&mut self, points: u32, reason: &'static str) {
        self.score += points;
        self.reasons.push(reason);
    }
}

/// Result of protection candidate detection.
#[derive(Debug)]
pub struct CandidateDetectionResult {
    /// All candidates found, sorted by score (highest first).
    pub candidates: Vec<ProtectionCandidate>,
    /// The .cctor token if found.
    pub cctor_token: Option<Token>,
}

impl CandidateDetectionResult {
    /// Returns the best candidate (highest score), if any.
    #[must_use]
    pub fn best(&self) -> Option<&ProtectionCandidate> {
        self.candidates.first()
    }

    /// Returns an iterator over candidates in score order.
    pub fn iter(&self) -> impl Iterator<Item = &ProtectionCandidate> {
        self.candidates.iter()
    }

    /// Returns true if no candidates were found.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.candidates.is_empty()
    }
}

/// Finds protection initializer candidates for the specified protection type.
///
/// This function:
/// 1. Locates `<Module>.cctor` (the global static constructor)
/// 2. Extracts all methods called directly from `.cctor`
/// 3. Scores each based on protection-specific patterns
/// 4. Returns candidates sorted by score (highest first)
///
/// # Arguments
///
/// * `assembly` - The assembly to analyze.
/// * `protection` - The type of protection to detect.
///
/// # Returns
///
/// A [`CandidateDetectionResult`] containing scored candidates.
pub fn find_candidates(
    assembly: &CilObject,
    protection: ProtectionType,
) -> CandidateDetectionResult {
    // Step 1: Find <Module>.cctor
    let cctor_token = assembly.types().module_cctor();

    // Step 2: Extract direct callees from .cctor
    let cctor_callees = cctor_token
        .map(|t| extract_direct_callees(assembly, t))
        .unwrap_or_default();

    // Step 3: Build candidate list
    // Start with .cctor callees, they get bonus points
    let mut candidates: Vec<ProtectionCandidate> = cctor_callees
        .iter()
        .filter_map(|&token| {
            // Skip .cctor itself if it somehow appears
            let method = assembly.methods().get(&token)?;
            if method.value().is_cctor() {
                return None;
            }
            let mut candidate = ProtectionCandidate::new(token);
            candidate.called_from_cctor = true;
            candidate.add_score(10, "called from .cctor");
            Some(candidate)
        })
        .collect();

    // Step 4: Score each candidate based on protection type
    for candidate in &mut candidates {
        score_candidate(assembly, candidate, protection);
    }

    // Step 5: If no candidates from .cctor, do a global search
    if candidates.is_empty() {
        candidates = global_search(assembly, protection);
    }

    // Step 6: Sort by score (highest first), then by token for stability
    candidates.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.token.value().cmp(&b.token.value()))
    });

    // Filter out candidates with zero score
    candidates.retain(|c| c.score > 0);

    CandidateDetectionResult {
        candidates,
        cctor_token,
    }
}

/// Extracts all MethodDef tokens that are directly called from a method.
fn extract_direct_callees(assembly: &CilObject, method_token: Token) -> Vec<Token> {
    let mut callees = Vec::new();

    let Some(method_entry) = assembly.methods().get(&method_token) else {
        return callees;
    };
    let method = method_entry.value();

    let Some(cfg) = method.cfg() else {
        return callees;
    };

    for node_id in cfg.node_ids() {
        let Some(block) = cfg.block(node_id) else {
            continue;
        };

        for instr in &block.instructions {
            // Look for call/callvirt to MethodDef tokens
            if instr.opcode == OPCODE_CALL || instr.opcode == OPCODE_CALLVIRT {
                if let Operand::Token(token) = &instr.operand {
                    // Only include MethodDef tokens (table 0x06)
                    if token.is_table(TableId::MethodDef) && !callees.contains(token) {
                        callees.push(*token);
                    }
                }
            }
        }
    }

    callees
}

/// Scores a candidate based on protection-specific patterns.
fn score_candidate(
    assembly: &CilObject,
    candidate: &mut ProtectionCandidate,
    protection: ProtectionType,
) {
    let Some(method_entry) = assembly.methods().get(&candidate.token) else {
        return;
    };
    let method = method_entry.value();

    let Some(cfg) = method.cfg() else {
        return;
    };

    // Collect all call targets for pattern matching
    let mut call_targets: Vec<String> = Vec::new();
    let mut has_delegate_creation = false;
    let mut has_field_access = false;

    for node_id in cfg.node_ids() {
        let Some(block) = cfg.block(node_id) else {
            continue;
        };

        for instr in &block.instructions {
            match instr.opcode {
                OPCODE_CALL | OPCODE_CALLVIRT => {
                    if let Operand::Token(token) = &instr.operand {
                        if let Some(name) = resolve_call_name(assembly, *token) {
                            call_targets.push(name);
                        }
                    }
                }
                OPCODE_NEWOBJ => {
                    if let Operand::Token(token) = &instr.operand {
                        if let Some(name) = resolve_call_name(assembly, *token) {
                            if name.contains("EventHandler") || name.contains("ResolveEventHandler")
                            {
                                has_delegate_creation = true;
                            }
                        }
                    }
                }
                // ldsfld, stsfld - static field access
                0x7E | 0x80 => {
                    has_field_access = true;
                }
                _ => {}
            }
        }
    }

    // Apply protection-specific scoring
    match protection {
        ProtectionType::AntiTamper => {
            score_antitamper(candidate, &call_targets);
        }
        ProtectionType::Resources => {
            score_resources(
                candidate,
                &call_targets,
                has_delegate_creation,
                has_field_access,
            );
        }
        ProtectionType::Constants => {
            score_constants(candidate, &call_targets, has_field_access);
        }
    }
}

/// Scores a candidate for anti-tamper patterns.
fn score_antitamper(candidate: &mut ProtectionCandidate, call_targets: &[String]) {
    for target in call_targets {
        if target.contains("GetHINSTANCE") {
            candidate.add_score(5, "calls GetHINSTANCE");
        }
        if target.contains("VirtualProtect") {
            candidate.add_score(5, "calls VirtualProtect");
        }
        if target.contains("get_Module") || target.contains("GetModuleHandle") {
            candidate.add_score(3, "accesses module handle");
        }
        if target.contains("GetMethod") || target.contains("MethodBase") {
            candidate.add_score(2, "uses reflection on methods");
        }
        if target.contains("Invoke") {
            candidate.add_score(2, "uses method invocation");
        }
    }
}

/// Scores a candidate for resource protection patterns.
fn score_resources(
    candidate: &mut ProtectionCandidate,
    call_targets: &[String],
    has_delegate_creation: bool,
    has_field_access: bool,
) {
    for target in call_targets {
        // Event handler registration
        if target.contains("add_AssemblyResolve") || target.contains("AssemblyResolve") {
            candidate.add_score(5, "registers AssemblyResolve handler");
        }
        if target.contains("add_ResourceResolve") || target.contains("ResourceResolve") {
            candidate.add_score(5, "registers ResourceResolve handler");
        }
        // Assembly loading
        if target.contains("Assembly") && target.contains("Load") {
            candidate.add_score(5, "calls Assembly.Load");
        }
        // Decompression
        if target.contains("Decompress") || target.contains("Lzma") || target.contains("Inflate") {
            candidate.add_score(3, "has decompression call");
        }
        // RuntimeHelpers.InitializeArray (used for embedded data)
        if target.contains("InitializeArray") {
            candidate.add_score(3, "uses InitializeArray for embedded data");
        }
    }

    if has_delegate_creation {
        candidate.add_score(2, "creates event delegate");
    }
    if has_field_access {
        candidate.add_score(1, "accesses static fields");
    }
}

/// Scores a candidate for constants protection patterns.
fn score_constants(
    candidate: &mut ProtectionCandidate,
    call_targets: &[String],
    has_field_access: bool,
) {
    for target in call_targets {
        // Buffer operations
        if target.contains("BlockCopy") || target.contains("Buffer") {
            candidate.add_score(3, "uses Buffer operations");
        }
        // BitConverter
        if target.contains("BitConverter") {
            candidate.add_score(2, "uses BitConverter");
        }
        // Array operations
        if target.contains("GetValue") && target.contains("Array") {
            candidate.add_score(2, "uses array indexing");
        }
    }

    if has_field_access {
        candidate.add_score(2, "accesses static fields for constants");
    }
}

/// Performs a global search for protection candidates when .cctor analysis fails.
fn global_search(assembly: &CilObject, protection: ProtectionType) -> Vec<ProtectionCandidate> {
    let mut candidates = Vec::new();

    for entry in assembly.methods().iter() {
        let method = entry.value();

        // Skip .cctor and abstract methods
        if method.is_cctor() || !method.has_body() {
            continue;
        }

        let mut candidate = ProtectionCandidate::new(method.token);
        score_candidate(assembly, &mut candidate, protection);

        // Only include if it has some score
        if candidate.score > 0 {
            candidates.push(candidate);
        }
    }

    candidates
}

/// Resolves a call target token to a method name.
fn resolve_call_name(assembly: &CilObject, token: Token) -> Option<String> {
    match token.table() {
        // MethodDef
        0x06 => Some(assembly.methods().get(&token)?.value().name.clone()),
        // MemberRef
        0x0A => Some(assembly.refs_members().get(&token)?.value().name.clone()),
        // MethodSpec (generic instantiation)
        0x2B => {
            // Try to get the underlying method
            // For now, just return None - could be enhanced later
            None
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ValidationConfig;

    const MAXIMUM_PATH: &str = "tests/samples/packers/confuserex/mkaring_maximum.exe";
    const ORIGINAL_PATH: &str = "tests/samples/packers/confuserex/original.exe";

    #[test]
    fn test_module_cctor() {
        let assembly =
            CilObject::from_path_with_validation(MAXIMUM_PATH, ValidationConfig::analysis())
                .unwrap();

        let cctor = assembly.types().module_cctor();
        assert!(cctor.is_some(), "Should find <Module>.cctor");
    }

    #[test]
    fn test_find_antitamper_candidates() {
        let assembly =
            CilObject::from_path_with_validation(MAXIMUM_PATH, ValidationConfig::analysis())
                .unwrap();

        let result = find_candidates(&assembly, ProtectionType::AntiTamper);

        assert!(!result.is_empty(), "Should find anti-tamper candidates");
        assert!(result.cctor_token.is_some(), "Should find .cctor");

        // Best candidate should have high score
        let best = result.best().expect("Should have best candidate");
        assert!(best.score >= 10, "Best candidate should have score >= 10");
        assert!(
            best.called_from_cctor,
            "Best candidate should be called from .cctor"
        );

        println!("Anti-tamper candidates:");
        for (i, c) in result.iter().enumerate() {
            println!(
                "  {}. 0x{:08x} score={} reasons={:?}",
                i + 1,
                c.token.value(),
                c.score,
                c.reasons
            );
        }
    }

    #[test]
    fn test_find_resource_candidates() {
        let assembly =
            CilObject::from_path_with_validation(MAXIMUM_PATH, ValidationConfig::analysis())
                .unwrap();

        let result = find_candidates(&assembly, ProtectionType::Resources);

        println!("Resource candidates:");
        for (i, c) in result.iter().enumerate() {
            println!(
                "  {}. 0x{:08x} score={} reasons={:?}",
                i + 1,
                c.token.value(),
                c.score,
                c.reasons
            );
        }
    }

    #[test]
    fn test_no_candidates_in_original() {
        let assembly = CilObject::from_path(ORIGINAL_PATH).unwrap();

        let antitamper = find_candidates(&assembly, ProtectionType::AntiTamper);
        let resources = find_candidates(&assembly, ProtectionType::Resources);

        // Original should have no high-scoring candidates
        let best_at = antitamper.best().map(|c| c.score).unwrap_or(0);
        let best_res = resources.best().map(|c| c.score).unwrap_or(0);

        assert!(
            best_at < 10,
            "Original should not have anti-tamper candidates (score={})",
            best_at
        );
        assert!(
            best_res < 10,
            "Original should not have resource candidates (score={})",
            best_res
        );
    }
}
