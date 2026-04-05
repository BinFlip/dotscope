//! Opaque field predicate detection via SSA analysis.
//!
//! Detects two variants of opaque predicates:
//!
//! ## Variant A: Static field → instance field chain
//!
//! ```text
//! v1 = LoadStaticField(static_field)     // ldsfld <Module>::<instance>
//! v2 = LoadField(v1, instance_field)     // ldfld <int32_field>
//! Branch(condition=v2, true_target, false_target)
//! ```
//!
//! The singleton objects are initialized in type constructors (`.cctor`s). By
//! emulating those constructors, the actual field values can be determined and
//! conditional branches replaced with unconditional jumps.
//!
//! ## Variant B: Sentinel null-check methods
//!
//! ```text
//! // Sentinel method body (4 instructions):
//! v0 = LoadStaticField(self_typed_field)  // ldsfld <Module>::field
//! v1 = Const(Null)                        // ldnull
//! v2 = Ceq(v0, v1)                        // ceq
//! Return(v2)                               // ret → always true (field is null)
//!
//! // Call site:
//! v3 = Call(sentinel_method)               // call bool SentinelMethod()
//! Branch(condition=v3, ...)                 // brtrue/brfalse
//! ```
//!
//! Sentinel fields are self-typed static references that are never written to
//! in most cases, but may be resolved via Reflection at runtime. Emulation
//! determines their actual value safely.
//!
//! # Detection
//!
//! Detection uses `detect_ssa()` (Phase 3.5) to scan SSA functions for both
//! patterns. Variant A uses `LoadStaticField → LoadField → Branch` def-use
//! chains. Variant B identifies sentinel methods by their body pattern, then
//! finds call sites.
//!
//! # Passes
//!
//! Creates an `OpaqueFieldPredicatePass` with pre-computed findings from the
//! SSA detection phase, avoiding a redundant SSA scan in the pass's
//! `initialize()`.

use std::{
    any::Any,
    collections::{HashMap, HashSet},
    sync::Arc,
};

use crate::{
    analysis::{SsaFunction, SsaOp, SsaVarId},
    cilassembly::CleanupRequest,
    compiler::{PassPhase, SsaPass},
    deobfuscation::{
        context::AnalysisContext,
        passes::OpaqueFieldPredicatePass,
        techniques::{Detection, Detections, Evidence, Technique, TechniqueCategory},
        utils::build_def_map,
    },
    emulation::{EmValue, Hook, HookPriority, PreHookResult},
    metadata::{tables::TableId, token::Token},
    CilObject,
};

/// Scans an SSA function for the opaque predicate pattern and collects the
/// static field tokens that appear in `LoadStaticField -> LoadField -> Branch`.
///
/// Builds a definition map and then traces each `Branch` terminator's condition
/// backwards through `LoadField` and `LoadStaticField` to extract the static
/// field tokens. Returns the set of all such tokens found in the function.
fn collect_predicate_static_fields(ssa: &SsaFunction) -> HashSet<Token> {
    let defs = build_def_map(ssa);

    let mut static_fields = HashSet::new();
    for block in ssa.blocks() {
        let Some(terminator) = block.terminator_op() else {
            continue;
        };

        // Match: Branch { condition, .. }
        let condition = match terminator {
            SsaOp::Branch { condition, .. } => *condition,
            _ => continue,
        };

        // Trace condition → LoadField { object, .. }
        let Some(SsaOp::LoadField { object, .. }) = defs.get(&condition) else {
            continue;
        };

        // Trace object → LoadStaticField { field }
        let Some(SsaOp::LoadStaticField { field, .. }) = defs.get(object) else {
            continue;
        };

        static_fields.insert(field.token());
    }
    static_fields
}

/// Scans an SSA function for ALL `LoadField(LoadStaticField(..))` patterns
/// and collects the static field tokens.
///
/// Unlike [`collect_predicate_static_fields`] which only looks at Branch
/// terminators, this function scans every instruction. It captures both
/// opaque predicate fields AND string encryption XOR key fields.
fn collect_field_load_sources(ssa: &SsaFunction) -> HashSet<Token> {
    let defs = build_def_map(ssa);

    let mut static_fields = HashSet::new();
    for block in ssa.blocks() {
        for instr in block.instructions() {
            // Match: LoadField { object, .. }
            let SsaOp::LoadField { object, .. } = instr.op() else {
                continue;
            };

            // Trace object → LoadStaticField { field }
            let Some(SsaOp::LoadStaticField { field, .. }) = defs.get(object) else {
                continue;
            };

            static_fields.insert(field.token());
        }
    }
    static_fields
}

/// Checks if an SSA function matches the sentinel null-check method pattern:
///
/// ```text
/// v0 = LoadStaticField { field }   // ldsfld self_typed_field
/// v1 = Const { value: Null }       // ldnull
/// v2 = Ceq { left: v0, right: v1 } // ceq
/// Return { value: Some(v2) }        // ret
/// ```
///
/// Returns `Some(field_token)` if the pattern matches, `None` otherwise.
/// The detection follows def-use chains from the Return terminator backwards,
/// so it's insensitive to instruction ordering and tolerates Nop/Phi padding.
fn identify_sentinel_method(ssa: &SsaFunction) -> Option<Token> {
    // Sentinel methods are tiny — reject anything with more than 2 blocks
    // (entry + possible unreachable) or too many instructions.
    if ssa.block_count() > 2 {
        return None;
    }

    let block = ssa.blocks().first()?;

    // Find the Return terminator
    let terminator = block.terminator_op()?;
    let return_var = match terminator {
        SsaOp::Return { value: Some(v) } => *v,
        _ => return None,
    };

    // Build def map for this block
    let mut defs: HashMap<SsaVarId, &SsaOp> = HashMap::new();
    for instr in block.instructions() {
        if let Some(dest) = instr.op().dest() {
            defs.insert(dest, instr.op());
        }
    }

    // Trace return_var → Ceq { left, right }
    let (left, right) = match defs.get(&return_var)? {
        SsaOp::Ceq { left, right, .. } => (*left, *right),
        _ => return None,
    };

    // One operand must be LoadStaticField, the other must be Const(Null)
    let field_token = match (defs.get(&left), defs.get(&right)) {
        (Some(SsaOp::LoadStaticField { field, .. }), Some(SsaOp::Const { value, .. }))
            if value.is_null() =>
        {
            field.token()
        }
        (Some(SsaOp::Const { value, .. }), Some(SsaOp::LoadStaticField { field, .. }))
            if value.is_null() =>
        {
            field.token()
        }
        _ => return None,
    };

    // Verify the method is small (no more than ~8 real instructions, excluding phis/nops)
    let real_instructions = block
        .instructions()
        .iter()
        .filter(|i| !matches!(i.op(), SsaOp::Nop | SsaOp::Phi { .. }))
        .count();
    if real_instructions > 6 {
        return None;
    }

    Some(field_token)
}

/// Scans all SSA functions to find sentinel null-check methods and their call sites.
///
/// Returns:
/// - `sentinel_methods`: Map of sentinel method token → sentinel field token
/// - `sentinel_call_sites`: Set of method tokens that call sentinel methods
fn collect_sentinel_info(
    ssa_functions: &dashmap::DashMap<Token, SsaFunction>,
) -> (HashMap<Token, Token>, HashSet<Token>) {
    // Phase 1: Identify sentinel methods by their body pattern
    let mut sentinel_methods: HashMap<Token, Token> = HashMap::new();
    for entry in ssa_functions.iter() {
        if let Some(field_token) = identify_sentinel_method(entry.value()) {
            sentinel_methods.insert(*entry.key(), field_token);
        }
    }

    if sentinel_methods.is_empty() {
        return (sentinel_methods, HashSet::new());
    }

    // Phase 2: Find call sites that reference sentinel methods
    let mut call_site_methods: HashSet<Token> = HashSet::new();
    for entry in ssa_functions.iter() {
        let method_token = *entry.key();
        if sentinel_methods.contains_key(&method_token) {
            continue;
        }
        let has_sentinel_call = entry.value().blocks().iter().any(|block| {
            block.instructions().iter().any(|instr| {
                matches!(instr.op(), SsaOp::Call { method, .. }
                    if sentinel_methods.contains_key(&method.token()))
            })
        });
        if has_sentinel_call {
            call_site_methods.insert(method_token);
        }
    }

    (sentinel_methods, call_site_methods)
}

/// Findings from opaque field predicate detection.
#[derive(Debug)]
pub struct OpaquePredicateFindings {
    /// Unique static field tokens appearing in opaque predicate patterns (Variant A).
    pub affected_field_tokens: Vec<Token>,
    /// Method tokens that contain at least one opaque predicate (Variant A or B call site).
    pub affected_methods: Vec<Token>,
    /// TypeDef tokens of types that own the detected opaque predicate fields.
    /// Used by `cleanup()` to request removal of the GUID class.
    pub owning_type_tokens: Vec<Token>,
    /// Sentinel method token → sentinel field token mapping (Variant B).
    /// The method body is `ldsfld → ldnull → ceq → ret` (always returns true if field is null).
    pub sentinel_methods: HashMap<Token, Token>,
}

/// Detects static field chain opaque predicates via SSA def-use analysis.
pub struct GenericOpaquePredicates;

impl Technique for GenericOpaquePredicates {
    fn id(&self) -> &'static str {
        "generic.opaquefields"
    }

    fn name(&self) -> &'static str {
        "Opaque Field Predicates"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Structure
    }

    fn detect(&self, _assembly: &CilObject) -> Detection {
        // IL-level detection is not used — all detection happens in detect_ssa()
        // after SSA functions are built, where we can follow exact def-use chains.
        Detection::new_empty()
    }

    fn detect_ssa(&self, ctx: &AnalysisContext, assembly: &CilObject) -> Detection {
        // --- Variant A: Static field chain predicates ---
        let mut affected_fields: HashSet<Token> = HashSet::new();
        let mut affected_methods: HashSet<Token> = HashSet::new();

        for entry in ctx.ssa_functions.iter() {
            let method_token = *entry.key();
            let predicate_fields = collect_predicate_static_fields(entry.value());
            let all_field_loads = collect_field_load_sources(entry.value());
            let combined: HashSet<Token> =
                predicate_fields.union(&all_field_loads).copied().collect();
            if !combined.is_empty() {
                affected_methods.insert(method_token);
                affected_fields.extend(combined);
            }
        }

        // --- Variant B: Sentinel null-check methods ---
        let (sentinel_methods, sentinel_call_sites) = collect_sentinel_info(&ctx.ssa_functions);

        // Merge sentinel call site methods into affected_methods
        affected_methods.extend(&sentinel_call_sites);

        // Merge sentinel field tokens into affected_fields for warmup targeting
        let sentinel_field_tokens: HashSet<Token> = sentinel_methods.values().copied().collect();
        affected_fields.extend(&sentinel_field_tokens);

        if affected_methods.is_empty() {
            return Detection::new_empty();
        }

        // Resolve Variant A field tokens (NOT sentinel) to FieldDef for type lookup.
        // Only Variant A fields contribute to owning_type_tokens because those types
        // (e.g., Module singleton) exist solely for opaque predicates. Sentinel fields
        // are injected into real application types which must NOT be deleted.
        let variant_a_fields: HashSet<Token> = affected_fields
            .difference(&sentinel_field_tokens)
            .copied()
            .collect();
        let mut resolved_fields: HashSet<Token> = HashSet::new();
        for token in &variant_a_fields {
            resolved_fields.insert(*token);
            if token.is_table(TableId::MemberRef) {
                if let Some(resolved) = assembly.resolver().resolve_field(*token) {
                    resolved_fields.insert(resolved);
                }
            }
        }

        // Find types that own the Variant A opaque predicate fields.
        // These types exist solely as opaque predicate infrastructure and can be deleted.
        let mut owning_types: HashSet<Token> = HashSet::new();
        let registry = assembly.types();
        for entry in registry.iter() {
            let type_ref = entry.value();
            let owns_field = type_ref.fields.iter().any(|(_, field)| {
                field.flags.is_static() && resolved_fields.contains(&field.token)
            });
            if owns_field {
                owning_types.insert(*entry.key());
            }
        }

        let method_count = affected_methods.len();
        let field_count = affected_fields.len();
        let sentinel_count = sentinel_methods.len();

        let mut evidence = vec![Evidence::Structural(format!(
            "{method_count} methods with opaque predicates ({field_count} unique fields)"
        ))];
        if sentinel_count > 0 {
            evidence.push(Evidence::Structural(format!(
                "{sentinel_count} sentinel null-check methods with {} call sites",
                sentinel_call_sites.len()
            )));
        }

        let findings = OpaquePredicateFindings {
            affected_field_tokens: affected_fields.into_iter().collect(),
            affected_methods: affected_methods.into_iter().collect(),
            owning_type_tokens: owning_types.into_iter().collect(),
            sentinel_methods,
        };

        Detection::new_detected(
            evidence,
            Some(Box::new(findings) as Box<dyn Any + Send + Sync>),
        )
    }

    fn initialize(
        &self,
        ctx: &AnalysisContext,
        assembly: &CilObject,
        detection: &Detection,
        _detections: &Detections,
    ) {
        let Some(findings) = detection.findings::<OpaquePredicateFindings>() else {
            return;
        };

        // Resolve MemberRef tokens to FieldDef tokens so we can match against type fields.
        let mut resolved_fields: HashSet<Token> = HashSet::new();
        for token in &findings.affected_field_tokens {
            resolved_fields.insert(*token);
            if token.is_table(TableId::MemberRef) {
                if let Some(resolved) = assembly.resolver().resolve_field(*token) {
                    resolved_fields.insert(resolved);
                }
            }
        }

        // Find cctors for types owning the detected fields and register them as warmup methods.
        let registry = assembly.types();
        for entry in registry.iter() {
            let type_ref = entry.value();
            let owns_needed_field = type_ref.fields.iter().any(|(_, field)| {
                field.flags.is_static() && resolved_fields.contains(&field.token)
            });
            if owns_needed_field {
                if let Some(cctor) = type_ref.cctor() {
                    ctx.register_warmup_method(cctor, vec![]);
                }
            }
        }

        // Register bypass-tamper hook so the Module cctor completes in DecryptionPass.
        // The cctor may call RSACryptoServiceProvider.VerifyHash for integrity checks
        // which would fail in the emulator.
        ctx.register_emulation_hook("generic.opaquefields", || {
            Hook::new("bypass-tamper-verify-hash")
                .match_name(
                    "System.Security.Cryptography",
                    "RSACryptoServiceProvider",
                    "VerifyHash",
                )
                .with_priority(HookPriority::HIGH)
                .pre(|_ctx, _thread| PreHookResult::Bypass(Some(EmValue::I32(1))))
        });
    }

    fn ssa_phase(&self) -> Option<PassPhase> {
        Some(PassPhase::Structure)
    }

    fn create_pass(
        &self,
        ctx: &AnalysisContext,
        detection: &Detection,
        _assembly: &Arc<CilObject>,
    ) -> Vec<Box<dyn SsaPass>> {
        let Some(pool) = ctx.template_pool.get().cloned() else {
            return Vec::new();
        };
        let Some(findings) = detection.findings::<OpaquePredicateFindings>() else {
            return Vec::new();
        };
        let needed_static_fields: HashSet<Token> =
            findings.affected_field_tokens.iter().copied().collect();
        let affected_methods: HashSet<Token> = findings.affected_methods.iter().copied().collect();
        vec![Box::new(OpaqueFieldPredicatePass::new(
            pool,
            needed_static_fields,
            affected_methods,
            findings.sentinel_methods.clone(),
        ))]
    }

    fn cleanup(&self, detection: &Detection) -> Option<CleanupRequest> {
        let findings = detection.findings::<OpaquePredicateFindings>()?;
        let has_types = !findings.owning_type_tokens.is_empty();
        let has_sentinel = !findings.sentinel_methods.is_empty();

        if !has_types && !has_sentinel {
            return None;
        }

        let mut request = CleanupRequest::new();

        // Variant A: Remove entire owning types (Module singleton class)
        for &type_token in &findings.owning_type_tokens {
            request.add_type(type_token);
        }

        // Variant B: Remove individual sentinel methods and fields
        // (Can't remove owning types — sentinel artifacts are injected into real types)
        request.add_methods(findings.sentinel_methods.keys().copied());
        request.add_fields(findings.sentinel_methods.values().copied());

        Some(request)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        compiler::PassPhase,
        deobfuscation::techniques::{
            generic::opaquefields::{GenericOpaquePredicates, OpaquePredicateFindings},
            Technique, TechniqueCategory,
        },
        test::helpers::load_sample,
    };

    #[test]
    fn test_detect_negative_confuserex_original() {
        let asm = load_sample("tests/samples/packers/confuserex/1.6.0/original.exe");

        let technique = GenericOpaquePredicates;
        let detection = technique.detect(&asm);

        assert!(
            !detection.is_detected(),
            "GenericOpaquePredicates should not detect anything in a ConfuserEx original sample"
        );
        assert!(
            detection.evidence().is_empty(),
            "No evidence should be present for a non-obfuscated sample"
        );
        assert!(
            detection.findings::<OpaquePredicateFindings>().is_none(),
            "No findings should be present for a non-obfuscated sample"
        );
    }

    #[test]
    fn test_detect_negative_obfuscar_sample() {
        let asm = load_sample("tests/samples/packers/obfuscar/2.2.50/obfuscar_strings_only.exe");

        let technique = GenericOpaquePredicates;
        let detection = technique.detect(&asm);

        // Obfuscar does not use opaque field predicates
        assert!(
            !detection.is_detected(),
            "GenericOpaquePredicates should not detect anything in an Obfuscar sample"
        );
    }

    #[test]
    fn test_technique_metadata() {
        let technique = GenericOpaquePredicates;
        assert_eq!(technique.id(), "generic.opaquefields");
        assert_eq!(technique.name(), "Opaque Field Predicates");
        assert_eq!(technique.category(), TechniqueCategory::Structure);
        assert!(technique.supersedes().is_empty());
    }

    #[test]
    fn test_technique_ssa_phase() {
        let technique = GenericOpaquePredicates;
        assert_eq!(
            technique.ssa_phase(),
            Some(PassPhase::Structure),
            "GenericOpaquePredicates should run in the Structure SSA phase"
        );
    }
}
