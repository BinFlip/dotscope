#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    missing_docs
)]

//! Shared integration test verification framework.
//!
//! Provides SSA-based semantic verification for comparing original vs deobfuscated
//! assemblies. Used by ConfuserEx, BitMono, and Obfuscar integration tests.

#![allow(dead_code)]

use std::{
    collections::{HashMap, HashSet},
    hash::{Hash, Hasher},
    path::Path,
    sync::Arc,
};

use dotscope::{
    analysis::{ConstValue, ControlFlowGraph, SsaConverter, SsaFunction, SsaOp, TypeContext},
    assembly::Operand,
    metadata::{
        method::{Method, MethodModifiers},
        signatures::TypeSignature,
        token::Token,
        typesystem::CilTypeReference,
    },
    CilObject,
};

/// Verification level for semantic preservation checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationLevel {
    /// All core properties must be preserved (strings, calls, constants).
    Normal,
    /// More lenient verification for heavily obfuscated samples.
    /// Accepts partial preservation due to heavy transformation.
    Relaxed,
}

/// Semantic preservation results.
#[derive(Debug, Default)]
pub struct SemanticVerificationResult {
    pub methods_checked: usize,
    pub methods_preserved: usize,
    pub average_similarity: f64,
}

/// Wrapper for f64 that implements Hash and Eq for use in HashSet.
#[derive(Debug, Clone, Copy)]
pub struct OrderedFloat(pub f64);

impl PartialEq for OrderedFloat {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bits() == other.0.to_bits()
    }
}

impl Eq for OrderedFloat {}

impl Hash for OrderedFloat {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_bits().hash(state);
    }
}

/// Rich semantic content extracted from SSA for comprehensive comparison.
#[derive(Debug, Clone, Default)]
pub struct MethodSemantics {
    // Content - literals and constants
    pub strings: HashSet<String>,
    pub integer_constants: HashSet<i64>,
    pub float_constants: HashSet<OrderedFloat>,
    pub has_null: bool,
    pub has_true: bool,
    pub has_false: bool,

    // Method calls (qualified names where possible)
    pub calls: HashSet<String>,
    pub virtual_calls: HashSet<String>,
    pub constructor_calls: HashSet<String>,

    // External calls only (MemberRef tokens) - not obfuscated
    pub external_calls: HashSet<String>,

    // Field access (by resolved name)
    pub field_reads: HashSet<String>,
    pub field_writes: HashSet<String>,
    pub static_field_reads: HashSet<String>,
    pub static_field_writes: HashSet<String>,

    // External field reads only (MemberRef tokens) - not obfuscated
    pub external_field_reads: HashSet<String>,

    // Type operations
    pub allocated_types: HashSet<String>,
    pub cast_types: HashSet<String>,

    // Control flow structure
    pub block_count: usize,
    pub has_loops: bool,
    pub has_switches: bool,
    pub has_exceptions: bool,

    // Arithmetic operation counts
    pub arith_ops: HashMap<&'static str, usize>,
}

impl MethodSemantics {
    /// Extract comprehensive semantics from an SSA function.
    pub fn extract(ssa: &SsaFunction, assembly: &CilObject) -> Self {
        let mut semantics = MethodSemantics {
            block_count: ssa.blocks().len(),
            ..Default::default()
        };

        // Detect loops via back-edges (simplified: block that jumps to earlier block)
        let mut has_back_edge = false;

        for (block_idx, block) in ssa.blocks().iter().enumerate() {
            for instr in block.instructions() {
                match instr.op() {
                    // Constants
                    SsaOp::Const { value, .. } => {
                        Self::extract_constant(&mut semantics, value, assembly);
                    }

                    // Method calls
                    SsaOp::Call { method, .. } => {
                        let token = method.token();
                        if let Some(name) = resolve_method_name(assembly, token) {
                            semantics.calls.insert(name.clone());
                            if is_external_method_token(token) {
                                semantics.external_calls.insert(name);
                            }
                        }
                    }
                    SsaOp::CallVirt { method, .. } => {
                        let token = method.token();
                        if let Some(name) = resolve_method_name(assembly, token) {
                            semantics.virtual_calls.insert(name.clone());
                            semantics.calls.insert(name.clone());
                            if is_external_method_token(token) {
                                semantics.external_calls.insert(name);
                            }
                        }
                    }
                    SsaOp::NewObj { ctor, .. } => {
                        let token = ctor.token();
                        if let Some(name) = resolve_method_name(assembly, token) {
                            semantics.constructor_calls.insert(name.clone());
                            semantics.calls.insert(name.clone());
                            if is_external_method_token(token) {
                                semantics.external_calls.insert(name);
                            }
                        }
                        // Also track the allocated type
                        if let Some(type_name) = resolve_type_from_ctor(assembly, ctor.token()) {
                            semantics.allocated_types.insert(type_name);
                        }
                    }

                    // Field access
                    SsaOp::LoadField { field, .. } => {
                        let token = field.token();
                        if let Some(name) = resolve_field_name(assembly, token) {
                            semantics.field_reads.insert(name.clone());
                            if is_external_field_token(token) {
                                semantics.external_field_reads.insert(name);
                            }
                        }
                    }
                    SsaOp::StoreField { field, .. } => {
                        if let Some(name) = resolve_field_name(assembly, field.token()) {
                            semantics.field_writes.insert(name);
                        }
                    }
                    SsaOp::LoadStaticField { field, .. } => {
                        let token = field.token();
                        if let Some(name) = resolve_field_name(assembly, token) {
                            semantics.static_field_reads.insert(name.clone());
                            if is_external_field_token(token) {
                                semantics.external_field_reads.insert(name);
                            }
                        }
                    }
                    SsaOp::StoreStaticField { field, .. } => {
                        if let Some(name) = resolve_field_name(assembly, field.token()) {
                            semantics.static_field_writes.insert(name);
                        }
                    }

                    // Type operations
                    SsaOp::CastClass { target_type, .. } | SsaOp::IsInst { target_type, .. } => {
                        if let Some(name) = resolve_type_name(assembly, target_type.token()) {
                            semantics.cast_types.insert(name);
                        }
                    }
                    SsaOp::Box { value_type, .. }
                    | SsaOp::Unbox { value_type, .. }
                    | SsaOp::UnboxAny { value_type, .. } => {
                        if let Some(name) = resolve_type_name(assembly, value_type.token()) {
                            semantics.cast_types.insert(name);
                        }
                    }

                    // Control flow
                    SsaOp::Switch { .. } => {
                        semantics.has_switches = true;
                    }
                    SsaOp::Jump { target } if *target <= block_idx => {
                        has_back_edge = true;
                    }
                    SsaOp::Branch {
                        true_target,
                        false_target,
                        ..
                    } if *true_target <= block_idx || *false_target <= block_idx => {
                        has_back_edge = true;
                    }
                    SsaOp::BranchCmp {
                        true_target,
                        false_target,
                        ..
                    } if *true_target <= block_idx || *false_target <= block_idx => {
                        has_back_edge = true;
                    }

                    // Exceptions
                    SsaOp::Throw { .. } | SsaOp::Rethrow => {
                        semantics.has_exceptions = true;
                    }

                    // Arithmetic operations
                    SsaOp::Add { .. } | SsaOp::AddOvf { .. } => {
                        *semantics.arith_ops.entry("add").or_insert(0) += 1;
                    }
                    SsaOp::Sub { .. } | SsaOp::SubOvf { .. } => {
                        *semantics.arith_ops.entry("sub").or_insert(0) += 1;
                    }
                    SsaOp::Mul { .. } | SsaOp::MulOvf { .. } => {
                        *semantics.arith_ops.entry("mul").or_insert(0) += 1;
                    }
                    SsaOp::Div { .. } => {
                        *semantics.arith_ops.entry("div").or_insert(0) += 1;
                    }
                    SsaOp::Rem { .. } => {
                        *semantics.arith_ops.entry("rem").or_insert(0) += 1;
                    }
                    SsaOp::And { .. } => {
                        *semantics.arith_ops.entry("and").or_insert(0) += 1;
                    }
                    SsaOp::Or { .. } => {
                        *semantics.arith_ops.entry("or").or_insert(0) += 1;
                    }
                    SsaOp::Xor { .. } => {
                        *semantics.arith_ops.entry("xor").or_insert(0) += 1;
                    }
                    SsaOp::Shl { .. } => {
                        *semantics.arith_ops.entry("shl").or_insert(0) += 1;
                    }
                    SsaOp::Shr { .. } => {
                        *semantics.arith_ops.entry("shr").or_insert(0) += 1;
                    }
                    SsaOp::Neg { .. } => {
                        *semantics.arith_ops.entry("neg").or_insert(0) += 1;
                    }
                    SsaOp::Not { .. } => {
                        *semantics.arith_ops.entry("not").or_insert(0) += 1;
                    }

                    _ => {}
                }
            }
        }

        semantics.has_loops = has_back_edge;
        semantics
    }

    pub fn extract_constant(
        semantics: &mut MethodSemantics,
        value: &ConstValue,
        assembly: &CilObject,
    ) {
        match value {
            ConstValue::String(token) => {
                if let Some(content) = resolve_user_string(assembly, *token) {
                    semantics.strings.insert(content);
                }
            }
            ConstValue::DecryptedString(content) => {
                semantics.strings.insert(content.to_string());
            }
            ConstValue::I8(v) => {
                semantics.integer_constants.insert(i64::from(*v));
            }
            ConstValue::I16(v) => {
                semantics.integer_constants.insert(i64::from(*v));
            }
            ConstValue::I32(v) => {
                semantics.integer_constants.insert(i64::from(*v));
            }
            ConstValue::I64(v) => {
                semantics.integer_constants.insert(*v);
            }
            ConstValue::U8(v) => {
                semantics.integer_constants.insert(i64::from(*v));
            }
            ConstValue::U16(v) => {
                semantics.integer_constants.insert(i64::from(*v));
            }
            ConstValue::U32(v) => {
                semantics.integer_constants.insert(i64::from(*v));
            }
            ConstValue::U64(v) if *v <= i64::MAX as u64 => {
                semantics.integer_constants.insert(*v as i64);
            }
            ConstValue::NativeInt(v) => {
                semantics.integer_constants.insert(*v);
            }
            ConstValue::NativeUInt(v) if *v <= i64::MAX as u64 => {
                semantics.integer_constants.insert(*v as i64);
            }
            ConstValue::F32(v) => {
                semantics
                    .float_constants
                    .insert(OrderedFloat(f64::from(*v)));
            }
            ConstValue::F64(v) => {
                semantics.float_constants.insert(OrderedFloat(*v));
            }
            ConstValue::Null => {
                semantics.has_null = true;
            }
            ConstValue::True => {
                semantics.has_true = true;
            }
            ConstValue::False => {
                semantics.has_false = true;
            }
            _ => {}
        }
    }

    /// Calculate similarity score between two semantics (0.0 to 1.0).
    pub fn similarity(&self, other: &MethodSemantics) -> f64 {
        let string_sim = jaccard_similarity(&self.strings, &other.strings);
        // Use external_calls for similarity since internal calls may be renamed
        let call_sim = jaccard_similarity(&self.external_calls, &other.external_calls);
        let field_read_sim = jaccard_similarity(&self.field_reads, &other.field_reads);
        let const_sim = jaccard_similarity(&self.integer_constants, &other.integer_constants);

        // Weighted average: external calls and strings are most important
        string_sim * 0.35 + call_sim * 0.35 + field_read_sim * 0.15 + const_sim * 0.15
    }

    /// Check if this semantics preserves the essential properties of the original.
    ///
    /// Note: We don't require external calls to be preserved because some obfuscators
    /// use proxy/wrapper methods that call BCL methods indirectly. These proxies may
    /// not be inlined by the deobfuscator, but the semantic behavior is unchanged.
    pub fn preserves_semantics_of(&self, original: &MethodSemantics) -> bool {
        // All original strings must appear in deobfuscated (most important check).
        // Strings are content — they should never be optimized away.
        // Constants are NOT required for preservation. Valid optimizations
        // legitimately remove them:
        // - Constant folding: `tab == 9` → `true` (constant 9 disappears)
        // - Strength reduction: `x * 2` → `x << 1` (constant 2 disappears)
        // - Dead code elimination: unused constants removed
        //
        // Constants still contribute to the similarity score (see `similarity()`),
        // so methods with many missing constants will have lower similarity.

        // External calls and field reads are NOT required because obfuscators often
        // use proxy methods that wrap BCL calls. The deobfuscator may not inline these
        // proxies, but the semantic behavior is still preserved.
        //
        // We still track them for similarity scoring, but don't require preservation.

        original.strings.is_subset(&self.strings)
    }
}

/// Simplified type classification for fingerprinting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TypeKind {
    Void,
    Bool,
    Char,
    I8,
    U8,
    I16,
    U16,
    I32,
    U32,
    I64,
    U64,
    F32,
    F64,
    String,
    Object,
    Array,
    IntPtr,
    UIntPtr,
    ValueType,
    Class,
    Generic,
    ByRef,
    Pointer,
    Other,
}

impl TypeKind {
    pub fn from_type_signature(sig: &TypeSignature) -> Self {
        match sig {
            TypeSignature::Void => TypeKind::Void,
            TypeSignature::Boolean => TypeKind::Bool,
            TypeSignature::Char => TypeKind::Char,
            TypeSignature::I1 => TypeKind::I8,
            TypeSignature::U1 => TypeKind::U8,
            TypeSignature::I2 => TypeKind::I16,
            TypeSignature::U2 => TypeKind::U16,
            TypeSignature::I4 => TypeKind::I32,
            TypeSignature::U4 => TypeKind::U32,
            TypeSignature::I8 => TypeKind::I64,
            TypeSignature::U8 => TypeKind::U64,
            TypeSignature::R4 => TypeKind::F32,
            TypeSignature::R8 => TypeKind::F64,
            TypeSignature::String => TypeKind::String,
            TypeSignature::Object => TypeKind::Object,
            TypeSignature::I => TypeKind::IntPtr,
            TypeSignature::U => TypeKind::UIntPtr,
            TypeSignature::SzArray(_) | TypeSignature::Array(_) => TypeKind::Array,
            TypeSignature::ValueType(_) => TypeKind::ValueType,
            TypeSignature::Class(_) => TypeKind::Class,
            TypeSignature::GenericInst { .. }
            | TypeSignature::GenericParamType(_)
            | TypeSignature::GenericParamMethod(_) => TypeKind::Generic,
            TypeSignature::ByRef(_) => TypeKind::ByRef,
            TypeSignature::Ptr(_) => TypeKind::Pointer,
            _ => TypeKind::Other,
        }
    }
}

/// Structural fingerprint for matching methods across obfuscated assemblies.
#[derive(Debug, Clone)]
pub struct MethodFingerprint {
    pub param_count: usize,
    pub return_type_kind: TypeKind,
    pub param_type_kinds: Vec<TypeKind>,
    pub is_instance: bool,
    pub block_count: usize,
    pub instruction_count: usize,
    pub has_loops: bool,
    pub has_switches: bool,
}

impl MethodFingerprint {
    /// Build a fingerprint from a method and its SSA representation.
    pub fn build(method: &Method, ssa: &SsaFunction, semantics: &MethodSemantics) -> Self {
        let is_instance = !method.flags_modifiers.contains(MethodModifiers::STATIC);
        let param_count = method.signature.params.len();
        let return_type_kind = TypeKind::from_type_signature(&method.signature.return_type.base);
        let param_type_kinds: Vec<_> = method
            .signature
            .params
            .iter()
            .map(|p| TypeKind::from_type_signature(&p.base))
            .collect();

        // Count instructions
        let instruction_count: usize = ssa.blocks().iter().map(|b| b.instructions().len()).sum();

        MethodFingerprint {
            param_count,
            return_type_kind,
            param_type_kinds,
            is_instance,
            block_count: semantics.block_count,
            instruction_count,
            has_loops: semantics.has_loops,
            has_switches: semantics.has_switches,
        }
    }

    /// Calculate structural similarity between two fingerprints (0.0 to 1.0).
    pub fn similarity(&self, other: &MethodFingerprint) -> f64 {
        let mut score = 0.0;
        let mut weight = 0.0;

        // Signature match is most important (0.5 weight)
        if self.return_type_kind == other.return_type_kind {
            score += 0.2;
        }
        weight += 0.2;

        if self.param_count == other.param_count {
            score += 0.15;
            // If param counts match, check param types
            let matching_params = self
                .param_type_kinds
                .iter()
                .zip(&other.param_type_kinds)
                .filter(|(a, b)| a == b)
                .count();
            if self.param_count > 0 {
                score += 0.15 * (matching_params as f64 / self.param_count as f64);
            } else {
                score += 0.15;
            }
        }
        weight += 0.3;

        // Instance vs static
        if self.is_instance == other.is_instance {
            score += 0.1;
        }
        weight += 0.1;

        // Structural similarity (block count, instruction count)
        let block_ratio = if self.block_count.max(other.block_count) > 0 {
            self.block_count.min(other.block_count) as f64
                / self.block_count.max(other.block_count) as f64
        } else {
            1.0
        };
        score += 0.1 * block_ratio;
        weight += 0.1;

        let instr_ratio = if self.instruction_count.max(other.instruction_count) > 0 {
            self.instruction_count.min(other.instruction_count) as f64
                / self.instruction_count.max(other.instruction_count) as f64
        } else {
            1.0
        };
        score += 0.1 * instr_ratio;
        weight += 0.1;

        // Behavioral similarity
        if self.has_loops == other.has_loops {
            score += 0.05;
        }
        weight += 0.05;

        if self.has_switches == other.has_switches {
            score += 0.05;
        }
        weight += 0.05;

        if weight > 0.0 {
            score / weight
        } else {
            0.0
        }
    }
}

/// Signature key for method matching (param count + types).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SignatureKey {
    pub param_count: usize,
    pub return_type: TypeKind,
    pub param_types: Vec<TypeKind>,
    pub is_instance: bool,
}

/// Check if assembly has switch dispatchers (CFF obfuscation indicator).
pub fn check_has_switch_dispatcher(assembly: &CilObject) -> (bool, usize) {
    let mut total_switches = 0;

    // Check user methods (not .ctor, .cctor, or compiler-generated)
    for method_entry in assembly.methods().iter() {
        let method = method_entry.value();

        // Skip special methods
        if method.name.starts_with('.') || method.name.contains('<') {
            continue;
        }

        // Try to get CFG and check for switches
        if let Some(cfg) = method.cfg() {
            for node_id in cfg.node_ids() {
                if let Some(block) = cfg.block(node_id) {
                    for instr in &block.instructions {
                        if instr.mnemonic == "switch" {
                            total_switches += 1;
                        }
                    }
                }
            }
        }
    }

    (total_switches > 0, total_switches)
}

/// Verify semantic preservation by comparing deobfuscated methods against original.
/// Uses signature + fingerprint matching to handle name-obfuscated samples.
pub fn verify_semantic_preservation(
    original_asm: &CilObject,
    deobfuscated_asm: Arc<CilObject>,
    method_names: &[&str],
    level: VerificationLevel,
) -> SemanticVerificationResult {
    let mut methods_checked = 0;
    let mut methods_preserved = 0;
    let mut total_similarity = 0.0;
    let mut details = Vec::new();

    // First, try name-based matching (for samples without name obfuscation)
    let mut name_matched = 0;
    for method_name in method_names {
        if build_ssa_for_method(&deobfuscated_asm, method_name).is_some() {
            name_matched += 1;
        }
    }

    let use_name_matching = name_matched >= method_names.len() / 2;

    if use_name_matching {
        // Name-based matching (simpler, for non-name-obfuscated samples)
        for method_name in method_names {
            let Some((original_ssa, _)) = build_ssa_for_method(original_asm, method_name) else {
                continue;
            };

            let original_semantics = MethodSemantics::extract(&original_ssa, original_asm);

            let Some((deobfuscated_ssa, _)) = build_ssa_for_method(&deobfuscated_asm, method_name)
            else {
                methods_checked += 1;
                details.push((method_name.to_string(), 0.0, false, "not found".to_string()));
                continue;
            };

            let deobfuscated_semantics =
                MethodSemantics::extract(&deobfuscated_ssa, &deobfuscated_asm);
            let similarity = deobfuscated_semantics.similarity(&original_semantics);
            let preserves = deobfuscated_semantics.preserves_semantics_of(&original_semantics);

            methods_checked += 1;
            total_similarity += similarity;

            if preserves {
                methods_preserved += 1;
                details.push((method_name.to_string(), similarity, true, String::new()));
            } else {
                let missing_strings: Vec<_> = original_semantics
                    .strings
                    .difference(&deobfuscated_semantics.strings)
                    .take(3)
                    .cloned()
                    .collect();

                // Check significant constants (non-trivial values)
                let significant_consts: HashSet<_> = original_semantics
                    .integer_constants
                    .iter()
                    .filter(|&&c| c != 0 && c != 1 && c != -1)
                    .copied()
                    .collect();
                let missing_consts: Vec<_> = significant_consts
                    .difference(&deobfuscated_semantics.integer_constants)
                    .take(3)
                    .copied()
                    .collect();

                let reason = format!(
                    "missing strings: {:?}, missing constants: {:?}",
                    missing_strings, missing_consts
                );
                details.push((method_name.to_string(), similarity, false, reason));
            }
        }
    } else {
        // Signature + fingerprint matching (for name-obfuscated samples)
        // For each reference method, find the best matching deobfuscated method

        // Build candidate list: all deobfuscated methods with their SSA and semantics
        let mut deob_candidates: Vec<(
            Arc<Method>,
            SsaFunction,
            MethodSemantics,
            MethodFingerprint,
        )> = Vec::new();

        for method_entry in deobfuscated_asm.methods().iter() {
            let method = method_entry.value();

            // Skip special methods
            if method.name.starts_with('.') || method.name.contains('<') {
                continue;
            }

            // Skip methods with no body
            if let Some(ssa) = build_ssa_for_method_entry(&deobfuscated_asm, method) {
                let semantics = MethodSemantics::extract(&ssa, &deobfuscated_asm);
                let fingerprint = MethodFingerprint::build(method, &ssa, &semantics);
                deob_candidates.push((method.clone(), ssa, semantics, fingerprint));
            }
        }

        // For each reference method, find the best matching deobfuscated method
        for method_name in method_names {
            let Some((ref_ssa, ref_method)) =
                build_ssa_for_method_with_method(original_asm, method_name)
            else {
                continue;
            };

            let ref_semantics = MethodSemantics::extract(&ref_ssa, original_asm);
            let ref_fingerprint = MethodFingerprint::build(&ref_method, &ref_ssa, &ref_semantics);

            // Build signature key for matching
            let is_instance = !ref_method.flags_modifiers.contains(MethodModifiers::STATIC);
            let ref_sig = SignatureKey {
                param_count: ref_method.signature.params.len(),
                return_type: TypeKind::from_type_signature(&ref_method.signature.return_type.base),
                param_types: ref_method
                    .signature
                    .params
                    .iter()
                    .map(|p| TypeKind::from_type_signature(&p.base))
                    .collect(),
                is_instance,
            };

            // Find best matching candidate by signature + fingerprint + semantics
            let mut best_match: Option<(f64, &MethodSemantics)> = None;
            for (cand_method, _cand_ssa, cand_semantics, cand_fingerprint) in &deob_candidates {
                // Check signature match first
                let cand_is_instance = !cand_method
                    .flags_modifiers
                    .contains(MethodModifiers::STATIC);
                let cand_sig = SignatureKey {
                    param_count: cand_method.signature.params.len(),
                    return_type: TypeKind::from_type_signature(
                        &cand_method.signature.return_type.base,
                    ),
                    param_types: cand_method
                        .signature
                        .params
                        .iter()
                        .map(|p| TypeKind::from_type_signature(&p.base))
                        .collect(),
                    is_instance: cand_is_instance,
                };

                if cand_sig != ref_sig {
                    continue; // Signature must match exactly
                }

                // Calculate combined score: fingerprint similarity + semantic similarity
                let fp_sim = cand_fingerprint.similarity(&ref_fingerprint);
                let sem_sim = cand_semantics.similarity(&ref_semantics);
                let combined = fp_sim * 0.3 + sem_sim * 0.7; // Prioritize semantic similarity

                if best_match.as_ref().is_none_or(|m| combined > m.0) {
                    best_match = Some((combined, cand_semantics));
                }
            }

            // Check if we found a match with sufficient confidence
            if let Some((score, deob_semantics)) = best_match {
                if score > 0.3 {
                    // Minimum threshold for a valid match
                    let preserves = deob_semantics.preserves_semantics_of(&ref_semantics);

                    methods_checked += 1;
                    total_similarity += score;

                    if preserves {
                        methods_preserved += 1;
                        details.push((method_name.to_string(), score, true, String::new()));
                    } else {
                        let missing_strings: Vec<_> = ref_semantics
                            .strings
                            .difference(&deob_semantics.strings)
                            .take(3)
                            .cloned()
                            .collect();

                        // Check significant constants (non-trivial values)
                        let significant_consts: HashSet<_> = ref_semantics
                            .integer_constants
                            .iter()
                            .filter(|&&c| c != 0 && c != 1 && c != -1)
                            .copied()
                            .collect();
                        let missing_consts: Vec<_> = significant_consts
                            .difference(&deob_semantics.integer_constants)
                            .take(3)
                            .copied()
                            .collect();

                        let reason = format!(
                            "missing strings: {:?}, missing constants: {:?}",
                            missing_strings, missing_consts
                        );
                        details.push((method_name.to_string(), score, false, reason));
                    }
                }
                // Low confidence match - method may be inlined/removed, don't count against ratio
            }
            // No signature match - method structure changed significantly, don't count against ratio
        }
    }

    // Print detailed results
    for (name, sim, preserved, reason) in &details {
        if !preserved {
            eprintln!(
                "  [SEM {}] {} - similarity={:.0}% {}",
                if level == VerificationLevel::Relaxed {
                    "WARN"
                } else {
                    "FAIL"
                },
                name,
                sim * 100.0,
                reason
            );
        }
    }

    let average_similarity = if methods_checked > 0 {
        total_similarity / methods_checked as f64
    } else {
        0.0
    };

    SemanticVerificationResult {
        methods_checked,
        methods_preserved,
        average_similarity,
    }
}

pub fn jaccard_similarity<T: Eq + Hash>(a: &HashSet<T>, b: &HashSet<T>) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    let intersection = a.intersection(b).count();
    let union = a.union(b).count();
    if union == 0 {
        1.0
    } else {
        intersection as f64 / union as f64
    }
}

pub fn resolve_user_string(assembly: &CilObject, token: u32) -> Option<String> {
    let userstrings = assembly.userstrings()?;
    let content = userstrings.get(token as usize).ok()?;
    Some(content.to_string_lossy().to_string())
}

pub fn resolve_field_name(assembly: &CilObject, token: Token) -> Option<String> {
    let table_id = token.table();

    match table_id {
        0x04 => {
            // Field table - search through types to find the field
            for entry in assembly.types().iter() {
                let cil_type = entry.value();
                for (_idx, field) in cil_type.fields.iter() {
                    if field.token == token {
                        let namespace = if cil_type.namespace.is_empty() {
                            String::new()
                        } else {
                            format!("{}.", cil_type.namespace)
                        };
                        return Some(format!("{}{}::{}", namespace, cil_type.name, field.name));
                    }
                }
            }
            Some(format!("Field<{}>", token.row()))
        }
        0x0A => {
            // MemberRef - could be a field reference
            if let Some(member_ref) = assembly.member_ref(&token) {
                let type_name = get_declaring_type_name(&member_ref.declaredby);
                Some(format!("{}::{}", type_name, member_ref.name))
            } else {
                None
            }
        }
        _ => None,
    }
}

pub fn resolve_type_name(assembly: &CilObject, token: Token) -> Option<String> {
    let table_id = token.table();

    match table_id {
        0x01 | 0x02 | 0x1B => {
            // TypeRef (0x01), TypeDef (0x02), or TypeSpec (0x1B)
            // Use TypeRegistry.get() which handles all type tokens
            if let Some(cil_type) = assembly.types().get(&token) {
                if cil_type.namespace.is_empty() {
                    Some(cil_type.name.clone())
                } else {
                    Some(format!("{}.{}", cil_type.namespace, cil_type.name))
                }
            } else {
                Some(format!("Type<{:08X}>", token.value()))
            }
        }
        _ => None,
    }
}

pub fn resolve_type_from_ctor(assembly: &CilObject, ctor_token: Token) -> Option<String> {
    let table_id = ctor_token.table();

    match table_id {
        0x06 => {
            // MethodDef - find the declaring type
            for entry in assembly.types().iter() {
                let cil_type = entry.value();
                for (_idx, method_ref) in cil_type.methods.iter() {
                    if let Some(m) = method_ref.upgrade() {
                        if m.token == ctor_token {
                            if cil_type.namespace.is_empty() {
                                return Some(cil_type.name.clone());
                            } else {
                                return Some(format!("{}.{}", cil_type.namespace, cil_type.name));
                            }
                        }
                    }
                }
            }
            None
        }
        0x0A => {
            // MemberRef
            assembly
                .member_ref(&ctor_token)
                .map(|member_ref| get_declaring_type_name(&member_ref.declaredby))
        }
        _ => None,
    }
}

pub fn get_declaring_type_name(type_ref: &CilTypeReference) -> String {
    match type_ref {
        CilTypeReference::TypeRef(tr) => {
            let ns = tr.namespace().unwrap_or_default();
            let name = tr.name().unwrap_or_else(|| "Unknown".to_string());
            if ns.is_empty() {
                name
            } else {
                format!("{}.{}", ns, name)
            }
        }
        CilTypeReference::TypeDef(td) => {
            let ns = td.namespace().unwrap_or_default();
            let name = td.name().unwrap_or_else(|| "Unknown".to_string());
            if ns.is_empty() {
                name
            } else {
                format!("{}.{}", ns, name)
            }
        }
        CilTypeReference::TypeSpec(ts) => ts.name().unwrap_or_else(|| "TypeSpec".to_string()),
        CilTypeReference::Module(m) => format!("[Module:{}]", m.name),
        CilTypeReference::ModuleRef(mr) => format!("[ModuleRef:{}]", mr.name),
        CilTypeReference::MethodDef(md) => {
            if let Some(m) = md.upgrade() {
                format!("[MethodDef:{}]", m.name)
            } else {
                "[MethodDef:Unknown]".to_string()
            }
        }
        CilTypeReference::None => "Unknown".to_string(),
        _ => "Unknown".to_string(),
    }
}

pub fn resolve_method_name(assembly: &CilObject, token: Token) -> Option<String> {
    let table_id = token.table();

    match table_id {
        0x06 => {
            let method = assembly.method(&token).ok()?;

            for entry in assembly.types().iter() {
                let cil_type = entry.value();
                for (_idx, method_ref) in cil_type.methods.iter() {
                    if let Some(m) = method_ref.upgrade() {
                        if m.token == token {
                            let namespace = if cil_type.namespace.is_empty() {
                                String::new()
                            } else {
                                format!("{}.", cil_type.namespace)
                            };
                            return Some(format!(
                                "{}{}::{}",
                                namespace, cil_type.name, method.name
                            ));
                        }
                    }
                }
            }
            Some(method.name.clone())
        }
        0x0A => {
            if let Some(member_ref) = assembly.member_ref(&token) {
                let type_name = get_declaring_type_name(&member_ref.declaredby);
                return Some(format!("{}::{}", type_name, member_ref.name));
            }
            Some(format!("MemberRef<{}>", token.row()))
        }
        0x2B => Some(format!("MethodSpec<{}>", token.row())),
        _ => None,
    }
}

pub fn build_ssa_for_method(
    assembly: &CilObject,
    method_name: &str,
) -> Option<(SsaFunction, Token)> {
    let (ssa, method) = build_ssa_for_method_with_method(assembly, method_name)?;
    Some((ssa, method.token))
}

pub fn build_ssa_for_method_with_method(
    assembly: &CilObject,
    method_name: &str,
) -> Option<(SsaFunction, Arc<Method>)> {
    let method = assembly
        .methods()
        .iter()
        .find(|e| e.value().name == method_name)
        .map(|e| e.value().clone())?;

    let cfg = method.cfg()?;
    let is_static = method.flags_modifiers.contains(MethodModifiers::STATIC);
    let num_args = method.signature.params.len() + if is_static { 0 } else { 1 };

    let declared_locals = method.local_vars.count();
    let max_local_used = find_max_local_index(&cfg);
    let num_locals = declared_locals.max(max_local_used + 1);

    let type_context = TypeContext::new(&method, assembly);
    let ssa = SsaConverter::build(&cfg, num_args, num_locals, &type_context).ok()?;
    Some((ssa, method))
}

pub fn build_ssa_for_method_entry(
    assembly: &CilObject,
    method: &Arc<Method>,
) -> Option<SsaFunction> {
    let cfg = method.cfg()?;
    let is_static = method.flags_modifiers.contains(MethodModifiers::STATIC);
    let num_args = method.signature.params.len() + if is_static { 0 } else { 1 };

    let declared_locals = method.local_vars.count();
    let max_local_used = find_max_local_index(&cfg);
    let num_locals = declared_locals.max(max_local_used + 1);

    let type_context = TypeContext::new(method, assembly);
    SsaConverter::build(&cfg, num_args, num_locals, &type_context).ok()
}

/// Assert that deobfuscation produced zero warnings and zero errors.
///
/// Shared across all obfuscator integration tests to enforce clean deobfuscation.
/// No warnings or errors are acceptable for any test sample.
pub fn assert_deobfuscation_diagnostics(filename: &str, warning_count: usize, error_count: usize) {
    assert_eq!(
        warning_count, 0,
        "{}: Deobfuscation produced {} warning(s) — zero warnings allowed",
        filename, warning_count
    );
    assert_eq!(
        error_count, 0,
        "{}: Deobfuscation produced {} error(s) — zero errors allowed",
        filename, error_count
    );
}

pub fn find_max_local_index(cfg: &ControlFlowGraph) -> usize {
    let mut max_index: usize = 0;
    for node_id in cfg.node_ids() {
        if let Some(block) = cfg.block(node_id) {
            for instr in &block.instructions {
                if let Operand::Local(idx) = &instr.operand {
                    max_index = max_index.max(*idx as usize);
                }
            }
        }
    }
    max_index
}

/// Check if a method token refers to an external method.
/// External = MemberRef (0x0A) or MethodSpec (0x2B)
/// Internal = MethodDef (0x06)
pub fn is_external_method_token(token: Token) -> bool {
    let table_id = token.table();
    // MemberRef (0x0A) = external method reference
    // MethodSpec (0x2B) = generic method instantiation (typically external)
    // MethodDef (0x06) = internal method definition
    table_id == 0x0A || table_id == 0x2B
}

/// Check if a field token refers to an external field.
/// External = MemberRef (0x0A) for field references
/// Internal = Field (0x04)
pub fn is_external_field_token(token: Token) -> bool {
    let table_id = token.table();
    // MemberRef (0x0A) = external field reference
    // Field (0x04) = internal field definition
    table_id == 0x0A
}

/// Structural statistics of a .NET assembly for comparing deobfuscated
/// output against the original baseline.
#[derive(Debug, Clone)]
pub struct AssemblyStats {
    /// File size in bytes.
    pub file_size: u64,
    /// User-defined type names (fully qualified, excluding compiler infrastructure).
    pub type_names: HashSet<String>,
    /// Number of user-defined methods (across all user types).
    pub method_count: usize,
    /// Number of user-defined fields (across all user types).
    pub field_count: usize,
    /// Embedded resource names.
    pub resource_names: HashSet<String>,
}

/// Names of types that are compiler/runtime infrastructure, not user code.
/// These are excluded from structural comparison.
const INFRASTRUCTURE_TYPE_PREFIXES: &[&str] = &["<Module>"];

const INFRASTRUCTURE_TYPE_NAMES: &[&str] = &[
    "System.Runtime.CompilerServices.RefSafetyRulesAttribute",
    "Microsoft.CodeAnalysis.EmbeddedAttribute",
    "System.Runtime.CompilerServices.NullableAttribute",
    "System.Runtime.CompilerServices.NullableContextAttribute",
];

/// Returns true if a type name is compiler/runtime infrastructure.
fn is_infrastructure_type(name: &str) -> bool {
    for prefix in INFRASTRUCTURE_TYPE_PREFIXES {
        if name.starts_with(prefix) {
            return true;
        }
    }
    INFRASTRUCTURE_TYPE_NAMES.contains(&name)
}

impl AssemblyStats {
    /// Collects structural statistics from an assembly.
    pub fn from_assembly(assembly: &CilObject, file_size: u64) -> Self {
        let types = assembly.types();
        let mut type_names = HashSet::new();
        let mut method_count = 0usize;
        let mut field_count = 0usize;

        for entry in types.iter() {
            let token: Token = *entry.key();
            let cil_type = entry.value();

            // Only count TypeDef tokens (table 0x02), not TypeRef/TypeSpec
            if token.table() != 0x02 {
                continue;
            }

            let fullname = cil_type.fullname();

            // Skip infrastructure types
            if is_infrastructure_type(&fullname) {
                continue;
            }

            type_names.insert(fullname);

            // Count methods and fields on this type
            method_count += cil_type.methods().count();
            field_count += cil_type.fields().count();
        }

        // Collect resource names
        let mut resource_names = HashSet::new();
        for entry in assembly.resources().iter() {
            resource_names.insert(entry.key().clone());
        }

        Self {
            file_size,
            type_names,
            method_count,
            field_count,
            resource_names,
        }
    }

    /// Collects stats from a file path.
    pub fn from_file(path: &Path) -> Self {
        let file_size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        let assembly = CilObject::from_path(path).expect("failed to load assembly for stats");
        Self::from_assembly(&assembly, file_size)
    }
}

/// Configuration for structural assertions.
#[derive(Debug, Clone)]
pub struct StructuralConfig {
    /// Maximum allowed file size increase from original (0.10 = +10%).
    /// Smaller output is always accepted (obfuscator artifacts removed).
    pub size_tolerance: f64,
    /// Whether to check that type names match original.
    pub check_type_names: bool,
    /// Whether to check that resource names match original.
    pub check_resources: bool,
}

impl Default for StructuralConfig {
    fn default() -> Self {
        Self {
            size_tolerance: 0.10,
            check_type_names: true,
            check_resources: true,
        }
    }
}

/// Asserts that the deobfuscated assembly matches the original's structure.
///
/// Checks:
/// 1. File size within tolerance
/// 2. All original types present (no missing user types)
/// 3. No extra types (obfuscator artifacts should be cleaned)
/// 4. Resource names match
///
/// Prints a diagnostic summary to stderr before asserting, so failures
/// show exactly what's wrong.
pub fn assert_structural_match(
    original: &AssemblyStats,
    deobfuscated: &AssemblyStats,
    filename: &str,
    config: &StructuralConfig,
) {
    let mut failures: Vec<String> = Vec::new();

    // File size check — only flag if output is LARGER than tolerance.
    // Smaller output is expected (obfuscator artifacts removed).
    let size_ratio = deobfuscated.file_size as f64 / original.file_size as f64;
    let size_pct = (size_ratio - 1.0) * 100.0;
    if size_ratio > (1.0 + config.size_tolerance) {
        failures.push(format!(
            "file size: {} bytes ({:+.1}% vs original {}), tolerance +{:.0}%",
            deobfuscated.file_size,
            size_pct,
            original.file_size,
            config.size_tolerance * 100.0
        ));
    }

    if config.check_type_names {
        // Missing types (in original but not in deobfuscated)
        let missing: Vec<_> = original
            .type_names
            .difference(&deobfuscated.type_names)
            .cloned()
            .collect();
        if !missing.is_empty() {
            failures.push(format!("missing types: {:?}", missing));
        }

        // Extra types (in deobfuscated but not in original = obfuscator artifacts)
        let extra: Vec<_> = deobfuscated
            .type_names
            .difference(&original.type_names)
            .cloned()
            .collect();
        if !extra.is_empty() {
            failures.push(format!("extra types (artifacts not cleaned): {:?}", extra));
        }
    }

    if config.check_resources {
        let missing_res: Vec<_> = original
            .resource_names
            .difference(&deobfuscated.resource_names)
            .cloned()
            .collect();
        let extra_res: Vec<_> = deobfuscated
            .resource_names
            .difference(&original.resource_names)
            .cloned()
            .collect();
        if !missing_res.is_empty() {
            failures.push(format!("missing resources: {:?}", missing_res));
        }
        if !extra_res.is_empty() {
            failures.push(format!("extra resources: {:?}", extra_res));
        }
    }

    // Print diagnostic summary
    eprintln!(
        "  Structural: size={} ({:+.1}%), types={}/{}, methods={}/{}, fields={}/{}, resources={}/{}{}",
        deobfuscated.file_size,
        size_pct,
        deobfuscated.type_names.len(),
        original.type_names.len(),
        deobfuscated.method_count,
        original.method_count,
        deobfuscated.field_count,
        original.field_count,
        deobfuscated.resource_names.len(),
        original.resource_names.len(),
        if failures.is_empty() { " ✓" } else { " ✗" }
    );

    assert!(
        failures.is_empty(),
        "{filename}: structural mismatch:\n  {}",
        failures.join("\n  ")
    );
}
