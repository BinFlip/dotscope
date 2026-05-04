//! Opaque field predicate removal and field constant injection pass.
//!
//! Removes opaque predicates based on static field → instance field chains
//! whose runtime values are deterministic, and injects constant values for
//! all resolvable field loads. Two patterns are handled:
//!
//! ## Pattern 1: Branch predicates
//! ```text
//! v1 = LoadStaticField(static_field)     // ldsfld <Module>::<instance>
//! v2 = LoadField(v1, instance_field)     // ldfld <int32_field>
//! Branch(condition=v2, true_target, false_target)
//! ```
//! Resolved by determining the runtime value → `Branch` becomes `Jump`.
//!
//! ## Pattern 2: Field constant injection
//! ```text
//! v1 = LoadStaticField(static_field)     // ldsfld <Module>::<instance>
//! v2 = LoadField(v1, instance_field)     // ldfld <int32_field>
//! ... use v2 as XOR key, argument, etc.
//! ```
//! Resolved by replacing `LoadField` → `Const(value)`. This enables downstream
//! constant propagation to fold expressions like `Xor(Const, Const)` → `Const`,
//! which in turn allows the `DecryptionPass` to see constant arguments for
//! string decryptor calls.
//!
//! # Emulation Strategy
//!
//! The pass receives pre-computed findings from SSA-level detection
//! (`GenericOpaquePredicates::detect_ssa`), which provides the exact set of static
//! field tokens and affected method tokens. The pass then:
//!
//! 1. **Targeted warmup** (first `run_on_method`): Only executes `.cctor`s for
//!    types that own fields actually referenced by opaque predicates. Uses
//!    fork-based isolation with multi-pass execution to handle dependency chains.
//!
//! # Safety
//!
//! If no warmup `.cctor` succeeds, the pass becomes a no-op for all methods —
//! no false positives are possible. Unresolved fields return `None` from
//! `get_static()`, so unmatched predicates are safely skipped.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use dashmap::DashSet;
use log::debug;

use crate::{
    analysis::{ConstValue, SsaFunction, SsaOp, SsaVarId},
    compiler::{CompilerContext, EventKind, ModificationScope, PassCapability, SsaPass},
    deobfuscation::{utils::build_def_map, EmulationTemplatePool, ProcessCell},
    emulation::{EmValue, EmulationProcess, HeapRef},
    metadata::token::Token,
    CilObject, Result,
};

/// Removes opaque predicates based on static field chains resolved via emulation.
///
/// This pass targets two patterns:
///
/// **Variant A** — Static field chain: a conditional branch depends on a field loaded
/// from a singleton object stored in a static field. Resolved by reading the instance
/// field from the emulated heap.
///
/// **Variant B** — Sentinel null-check: a `Call` to a tiny bool method that checks
/// `ldsfld → ldnull → ceq → ret` (always returns true if the sentinel field is null).
/// Resolved by reading the sentinel field from the emulator and computing `ceq(val, null)`.
///
/// The emulation process is cleared in `finalize()` to release its `Arc<CilObject>`
/// reference before code generation needs to unwrap the assembly.
pub struct OpaqueFieldPredicatePass {
    /// Lazily-initialized emulation process (pool fork + targeted warmup).
    /// Cleared in `finalize()` to release the assembly reference.
    lazy_process: ProcessCell,
    /// Shared emulation template pool for O(1) forks with pre-warmed state.
    template_pool: Arc<EmulationTemplatePool>,
    /// Static field tokens found during SSA scan that appear in opaque predicates.
    /// Used to target warmup to only the types that own these fields.
    needed_static_fields: DashSet<Token>,
    /// Method tokens that contain the opaque predicate pattern.
    /// Used by `should_run()` to skip methods that don't have the pattern.
    affected_methods: DashSet<Token>,
    /// Methods already successfully processed. Prevents redundant re-processing
    /// across pipeline iterations when the same pass instance is reused.
    processed_methods: DashSet<Token>,
    /// Sentinel method token → sentinel field token (Variant B).
    /// The method body is `ldsfld → ldnull → ceq → ret`.
    sentinel_methods: HashMap<Token, Token>,
}

impl OpaqueFieldPredicatePass {
    /// Creates a new opaque field predicate removal pass with pre-computed findings.
    ///
    /// The caller (typically `GenericOpaquePredicates::create_pass()`) provides the
    /// exact set of static field tokens and affected method tokens discovered
    /// during SSA-level detection. This avoids duplicating the SSA scan in
    /// `initialize()`.
    ///
    /// # Arguments
    ///
    /// * `template_pool` - Shared emulation template pool for O(1) forks.
    /// * `needed_static_fields` - Static field tokens from the SSA predicate scan.
    /// * `affected_methods` - Method tokens that contain at least one predicate.
    /// * `sentinel_methods` - Sentinel method → field mapping (Variant B).
    #[must_use]
    pub fn new(
        template_pool: Arc<EmulationTemplatePool>,
        needed_static_fields: HashSet<Token>,
        affected_methods: HashSet<Token>,
        sentinel_methods: HashMap<Token, Token>,
    ) -> Self {
        let needed = DashSet::new();
        for token in &needed_static_fields {
            needed.insert(*token);
        }
        let affected = DashSet::new();
        for token in &affected_methods {
            affected.insert(*token);
        }
        Self {
            lazy_process: ProcessCell::new("opaque field"),
            template_pool,
            needed_static_fields: needed,
            affected_methods: affected,
            processed_methods: DashSet::new(),
            sentinel_methods,
        }
    }

    /// Finds `.cctor` tokens for types that own any of the needed static fields.
    ///
    /// Rather than warming up all types with interesting-looking fields, this
    /// targets only types whose static fields are actually used in opaque predicate
    /// patterns discovered during the SSA scan.
    fn find_targeted_cctors(assembly: &CilObject, needed_fields: &DashSet<Token>) -> Vec<Token> {
        // Pre-resolve any MemberRef tokens to FieldDef so we can match against type fields.
        // Detection may collect MemberRef tokens (table 0x0A) while type fields store FieldDef
        // tokens (table 0x04).
        let resolved_fields: DashSet<Token> = DashSet::new();
        for token in needed_fields.iter() {
            resolved_fields.insert(*token);
            if let Some(resolved) = assembly.resolver().resolve_field(*token) {
                resolved_fields.insert(resolved);
            }
        }

        let registry = assembly.types();
        let mut cctors = Vec::new();

        for entry in registry.iter() {
            let type_ref = entry.value();

            // Check if any of this type's static fields are in our needed set
            let owns_needed_field = type_ref.fields.iter().any(|(_, field)| {
                field.flags.is_static() && resolved_fields.contains(&field.token)
            });

            if owns_needed_field {
                if let Some(cctor) = type_ref.cctor() {
                    if !cctors.contains(&cctor) {
                        debug!(
                            "Opaque field warmup: type {}.{} owns needed fields → .cctor 0x{:08X}",
                            type_ref.namespace,
                            type_ref.name,
                            cctor.value()
                        );
                        cctors.push(cctor);
                    }
                }
            }
        }

        cctors
    }

    /// Creates an emulation process by forking the shared template and running
    /// targeted warmup for types owning opaque predicate fields.
    ///
    /// The base template already has Module.cctor and registered warmup methods
    /// completed. This adds type-specific `.cctor` execution on top.
    fn create_process_from_pool(&self) -> Option<EmulationProcess> {
        let assembly = self.template_pool.assembly()?;
        let cctors = Self::find_targeted_cctors(&assembly, &self.needed_static_fields);
        self.template_pool.fork_for_targeted_warmup(&cctors)
    }

    /// Ensures the emulation process is initialized, returning a read guard.
    ///
    /// Delegates to [`ProcessCell::ensure_initialized`] with a fork +
    /// targeted warmup closure.
    fn ensure_initialized(
        &self,
    ) -> Result<std::sync::RwLockReadGuard<'_, Option<EmulationProcess>>> {
        self.lazy_process
            .ensure_initialized(|| self.create_process_from_pool(), |_| {})
    }
}

/// Resolves emulated field values with automatic MemberRef → FieldDef fallback.
///
/// Bundles the `(&EmulationProcess, &CilObject)` pair into a lightweight context
/// that provides field lookup methods with transparent token resolution. All opaque
/// predicate resolution (chain walking, sentinel checks, constant injection) goes
/// through this resolver.
///
/// Created once per `run_on_method` call and shared across all resolution operations
/// within that method.
struct FieldResolver<'a> {
    process: &'a EmulationProcess,
    assembly: &'a CilObject,
}

impl<'a> FieldResolver<'a> {
    /// Creates a new field resolver.
    ///
    /// # Arguments
    ///
    /// * `process` - The emulation process with initialized static state.
    /// * `assembly` - The assembly for MemberRef → FieldDef resolution.
    fn new(process: &'a EmulationProcess, assembly: &'a CilObject) -> Self {
        Self { process, assembly }
    }

    /// Gets a static field value with MemberRef → FieldDef fallback.
    ///
    /// # Arguments
    ///
    /// * `token` - The static field token (may be MemberRef or FieldDef).
    ///
    /// # Returns
    ///
    /// `Some(EmValue)` if the field is populated, `None` if not found.
    ///
    /// # Errors
    ///
    /// Returns an error if the emulator's static field table is inaccessible.
    fn get_static(&self, token: Token) -> Result<Option<EmValue>> {
        if let Some(val) = self.process.get_static(token)? {
            return Ok(Some(val));
        }
        if let Some(resolved) = self.assembly.resolver().resolve_field(token) {
            return self.process.get_static(resolved);
        }
        Ok(None)
    }

    /// Gets a heap object field value with MemberRef → FieldDef fallback.
    ///
    /// # Arguments
    ///
    /// * `heap_ref` - The heap reference of the object containing the field.
    /// * `token` - The instance field token (may be MemberRef or FieldDef).
    ///
    /// # Returns
    ///
    /// `Some(EmValue)` if the field is readable, `None` if the lookup fails.
    fn get_field(&self, heap_ref: HeapRef, token: Token) -> Option<EmValue> {
        match self.process.address_space().get_field(heap_ref, token) {
            Ok(val) => return Some(val),
            Err(e) => {
                debug!(
                    "OpaqueFields: field access failed for 0x{:08X} on heap ref: {e}",
                    token.value()
                );
            }
        }
        if let Some(resolved) = self.assembly.resolver().resolve_field(token) {
            match self.process.address_space().get_field(heap_ref, resolved) {
                Ok(val) => return Some(val),
                Err(e) => {
                    debug!(
                        "OpaqueFields: field access failed for resolved 0x{:08X} on heap ref: {e}",
                        resolved.value()
                    );
                }
            }
        }
        None
    }

    /// Resolves a nested field chain to a raw [`EmValue`].
    ///
    /// Walks a chain of `[field1, field2, ..., fieldN]` starting from the static
    /// field, following `ObjectRef` hops through the emulated heap at each level.
    /// Callers convert the result as needed (e.g., `.to_bool_cil()` for branch
    /// predicates, `.to_const_value()` for constant injection).
    ///
    /// # Arguments
    ///
    /// * `static_token` - Token of the root static field.
    /// * `field_chain` - Ordered list of instance field tokens to traverse.
    ///
    /// # Returns
    ///
    /// `Some(EmValue)` with the final field's value, or `None` if any hop fails
    /// (field not populated, non-object at a non-terminal hop, etc.).
    ///
    /// # Errors
    ///
    /// Returns an error if the emulator's static field table is inaccessible.
    fn resolve_chain(&self, static_token: Token, field_chain: &[Token]) -> Result<Option<EmValue>> {
        if field_chain.is_empty() {
            return Ok(None);
        }

        let Some(static_val) = self.get_static(static_token)? else {
            return Ok(None);
        };

        let mut current_val = static_val;
        for (i, &field_token) in field_chain.iter().enumerate() {
            let is_last = i == field_chain.len().saturating_sub(1);

            match &current_val {
                EmValue::ObjectRef(heap_ref) => {
                    let Some(field_val) = self.get_field(*heap_ref, field_token) else {
                        return Ok(None);
                    };
                    current_val = field_val;
                }
                _ if !is_last => return Ok(None),
                _ => {}
            }
        }

        Ok(Some(current_val))
    }

    /// Resolves a sentinel null-check field to a boolean value.
    ///
    /// The sentinel method pattern is `ceq(ldsfld(field), null)`, which returns
    /// `true` if the field value is null. For unset static fields, the ECMA-335
    /// default is null (reference types), so the result is `true`.
    ///
    /// # Arguments
    ///
    /// * `sentinel_field_token` - Token of the sentinel static field.
    ///
    /// # Returns
    ///
    /// `Some(bool)` — `true` if the field is null (or unset), `false` otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if the emulator's static field table is inaccessible.
    fn resolve_sentinel(&self, sentinel_field_token: Token) -> Result<Option<bool>> {
        let val = match self.get_static(sentinel_field_token)? {
            Some(val) => val,
            None => EmValue::Null, // Unset reference field defaults to null
        };
        Ok(Some(val.is_null()))
    }
}

/// Traces a `LoadField` chain backward through SSA definitions to find the root
/// `LoadStaticField` and all intermediate instance field tokens.
///
/// Returns `Some((static_field_token, [field_token1, ..., field_tokenN]))` where
/// `field_token1` is the first instance field after the static, and `field_tokenN`
/// is the field from the starting `LoadField` instruction.
///
/// Returns `None` if the chain doesn't terminate at a `LoadStaticField` or exceeds
/// the maximum depth (10 hops — more than any known obfuscator uses).
///
/// # Arguments
///
/// * `starting_op` - The SSA operation to trace from (must be `LoadField`).
/// * `defs` - Map from SSA variable ID to its defining operation.
fn trace_field_chain(
    starting_op: &SsaOp,
    defs: &HashMap<SsaVarId, &SsaOp>,
) -> Option<(Token, Vec<Token>)> {
    const MAX_CHAIN_DEPTH: usize = 10;

    let mut chain: Vec<Token> = Vec::new();
    let mut current_op = starting_op;

    for _ in 0..MAX_CHAIN_DEPTH {
        match current_op {
            SsaOp::LoadField { object, field, .. } => {
                chain.push(field.token());
                // Follow the object back to its definition
                current_op = defs.get(object)?;
            }
            SsaOp::LoadStaticField { field, .. } => {
                // Reached the root — reverse chain so it's in traversal order
                chain.reverse();
                return Some((field.token(), chain));
            }
            _ => return None,
        }
    }

    None // Exceeded max depth
}

impl SsaPass for OpaqueFieldPredicatePass {
    fn name(&self) -> &'static str {
        "opaque-field-predicate-removal"
    }

    fn description(&self) -> &'static str {
        "Removes opaque predicates based on static field chains resolved via emulation"
    }

    fn modification_scope(&self) -> ModificationScope {
        ModificationScope::CfgModifying
    }

    fn provides(&self) -> &[PassCapability] {
        &[PassCapability::ResolvedStaticFields]
    }

    fn should_run(&self, method_token: Token, _ctx: &CompilerContext) -> bool {
        self.affected_methods.contains(&method_token)
            && !self.processed_methods.contains(&method_token)
    }

    fn initialize(&mut self, _ctx: &CompilerContext) -> Result<()> {
        let remaining = self
            .affected_methods
            .len()
            .saturating_sub(self.processed_methods.len());
        if remaining > 0 {
            debug!(
                "Opaque field predicate pass: {} unique static fields in {} remaining methods ({} already processed)",
                self.needed_static_fields.len(),
                remaining,
                self.processed_methods.len(),
            );
        }

        Ok(())
    }

    fn run_on_method(
        &self,
        ssa: &mut SsaFunction,
        method_token: Token,
        ctx: &CompilerContext,
        assembly: &CilObject,
    ) -> Result<bool> {
        let guard = self.ensure_initialized()?;
        let Some(process) = guard.as_ref() else {
            return Ok(false);
        };
        let resolver = FieldResolver::new(process, assembly);

        // Build def map: SsaVarId → defining SsaOp
        let defs = build_def_map(ssa);

        // Find and resolve opaque predicates (Variant A: field chain + Variant B: sentinel)
        // Each entry: (block_idx, jump_target, dropped_target)
        let mut replacements: Vec<(usize, usize, usize)> = Vec::new();
        for (block_idx, block) in ssa.blocks().iter().enumerate() {
            let Some(terminator) = block.terminator_op() else {
                continue;
            };

            // Match: Branch { condition, true_target, false_target }
            let (condition, true_target, false_target) = match terminator {
                SsaOp::Branch {
                    condition,
                    true_target,
                    false_target,
                } => (*condition, *true_target, *false_target),
                _ => continue,
            };

            // Trace condition → LoadField { object, field }
            let Some(cond_def) = defs.get(&condition) else {
                continue;
            };

            // --- Variant A: LoadStaticField → LoadField+ → Branch ---
            // Trace backward through nested LoadField chains (supports arbitrary depth).
            // PureLogs uses multi-level chains: static → instance → instance → condition.
            if let Some((static_token, field_chain)) = trace_field_chain(cond_def, &defs) {
                if let Some(is_truthy) = resolver
                    .resolve_chain(static_token, &field_chain)?
                    .map(|v| v.to_bool_cil())
                {
                    let (target, dropped) = if is_truthy {
                        (true_target, false_target)
                    } else {
                        (false_target, true_target)
                    };
                    replacements.push((block_idx, target, dropped));
                    continue;
                }
            }

            // --- Variant B: Call(sentinel_method) → Branch ---
            if let SsaOp::Call { method, .. } = cond_def {
                if let Some(sentinel_field) = self.sentinel_methods.get(&method.token()) {
                    if let Some(is_truthy) = resolver.resolve_sentinel(*sentinel_field)? {
                        let (target, dropped) = if is_truthy {
                            (true_target, false_target)
                        } else {
                            (false_target, true_target)
                        };
                        replacements.push((block_idx, target, dropped));
                    }
                }
            }
        }

        // --- Variant B: Call(sentinel_method) → non-branch uses (stloc, CFF state) ---
        // Replace sentinel calls with constant true/false so downstream passes
        // (constant propagation, CFF) can fold the values.
        let mut sentinel_call_replacements: Vec<(usize, usize, SsaOp)> = Vec::new();
        if !self.sentinel_methods.is_empty() {
            for (block_idx, block) in ssa.blocks().iter().enumerate() {
                for (instr_idx, instr) in block.instructions().iter().enumerate() {
                    let SsaOp::Call {
                        dest: Some(dest),
                        method,
                        ..
                    } = instr.op()
                    else {
                        continue;
                    };
                    let Some(sentinel_field) = self.sentinel_methods.get(&method.token()) else {
                        continue;
                    };
                    if let Some(is_truthy) = resolver.resolve_sentinel(*sentinel_field)? {
                        let value = if is_truthy {
                            ConstValue::I32(1)
                        } else {
                            ConstValue::I32(0)
                        };
                        sentinel_call_replacements.push((
                            block_idx,
                            instr_idx,
                            SsaOp::Const { dest: *dest, value },
                        ));
                    }
                }
            }
        }

        // --- Field constant injection: LoadField+ → Const ---
        // For each LoadField, trace the chain back to a LoadStaticField and
        // resolve the value from the emulated heap. Supports nested chains.
        let mut const_replacements: Vec<(usize, usize, SsaOp)> = Vec::new();
        let mut replaced_object_vars: HashSet<SsaVarId> = HashSet::new();

        for (block_idx, block) in ssa.blocks().iter().enumerate() {
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                let SsaOp::LoadField { dest, object, .. } = instr.op() else {
                    continue;
                };

                // Build the chain: this LoadField's field is the last element,
                // preceded by any intermediate LoadField hops back to LoadStaticField.
                let load_field_op: SsaOp = instr.op().clone();
                let Some((static_token, field_chain)) = trace_field_chain(&load_field_op, &defs)
                else {
                    continue;
                };

                // Resolve the nested chain to a constant value
                let Some(const_val) = resolver
                    .resolve_chain(static_token, &field_chain)?
                    .and_then(|v| v.to_const_value())
                else {
                    continue;
                };

                const_replacements.push((
                    block_idx,
                    instr_idx,
                    SsaOp::Const {
                        dest: *dest,
                        value: const_val,
                    },
                ));
                replaced_object_vars.insert(*object);
            }
        }

        // Find dead LoadStaticField instructions whose dest is only used by
        // the LoadField instructions we're replacing with constants.
        let mut dead_static_loads: Vec<(usize, usize)> = Vec::new();
        for (block_idx, block) in ssa.blocks().iter().enumerate() {
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                let SsaOp::LoadStaticField { dest, .. } = instr.op() else {
                    continue;
                };
                if !replaced_object_vars.contains(dest) {
                    continue;
                }
                if let Some(variable) = ssa.variable(*dest) {
                    let all_uses_replaced = variable.uses().iter().all(|use_site| {
                        const_replacements
                            .iter()
                            .any(|(b, i, _)| *b == use_site.block && *i == use_site.instruction)
                    });
                    if all_uses_replaced {
                        dead_static_loads.push((block_idx, instr_idx));
                    }
                }
            }
        }

        // Must drop the read guard before mutating ssa
        drop(guard);

        // Apply replacements: Branch → Jump (Variant A + Variant B direct branches)
        for &(block_idx, target, dropped) in &replacements {
            if let Some(block) = ssa.block_mut(block_idx) {
                if let Some(last) = block.instructions_mut().last_mut() {
                    last.set_op(SsaOp::Jump { target });
                    ctx.events
                        .record(EventKind::OpaquePredicateRemoved)
                        .at(method_token, block_idx)
                        .message(format!(
                            "removed opaque field predicate → jump to block {target}"
                        ));
                }
            }

            // Clean up phi operands in the dropped target that referenced our block.
            // Without this, rebuild_ssa() may fail because phi nodes reference variables
            // from a predecessor edge that no longer exists.
            if dropped != target {
                if let Some(dropped_block) = ssa.block_mut(dropped) {
                    for phi in dropped_block.phi_nodes_mut() {
                        phi.retain_operands(|pred| pred != block_idx);
                    }
                }
            }
        }

        // Apply sentinel call replacements: Call → Const (Variant B non-branch uses)
        for (block_idx, instr_idx, new_op) in &sentinel_call_replacements {
            if let Some(block) = ssa.block_mut(*block_idx) {
                if let Some(instr) = block.instructions_mut().get_mut(*instr_idx) {
                    instr.set_op(new_op.clone());
                    ctx.events
                        .record(EventKind::OpaquePredicateRemoved)
                        .at(method_token, *block_idx)
                        .message("resolved sentinel null-check call → constant");
                }
            }
        }

        // Apply const replacements: LoadField → Const (Variant A field injection)
        for (block_idx, instr_idx, new_op) in &const_replacements {
            if let Some(block) = ssa.block_mut(*block_idx) {
                if let Some(instr) = block.instructions_mut().get_mut(*instr_idx) {
                    instr.set_op(new_op.clone());
                    ctx.events
                        .record(EventKind::ConstantFolded)
                        .at(method_token, *block_idx)
                        .message("resolved opaque field load → constant");
                }
            }
        }

        // NOP out dead LoadStaticField instructions
        for (block_idx, instr_idx) in &dead_static_loads {
            if let Some(block) = ssa.block_mut(*block_idx) {
                if let Some(instr) = block.instructions_mut().get_mut(*instr_idx) {
                    instr.set_op(SsaOp::Nop);
                }
            }
        }

        let changed = !replacements.is_empty()
            || !const_replacements.is_empty()
            || !sentinel_call_replacements.is_empty();
        // Mark as processed to prevent redundant re-processing in subsequent
        // pipeline iterations. Even if no changes were made, the SSA was scanned
        // and won't yield different results with the same emulation state.
        self.processed_methods.insert(method_token);
        Ok(changed)
    }

    fn finalize(&mut self, _ctx: &CompilerContext) -> Result<()> {
        // Clear the emulation process to release its Arc<CilObject> reference.
        // This is needed so the assembly can be unwrapped for code generation.
        self.lazy_process.clear()
    }
}
