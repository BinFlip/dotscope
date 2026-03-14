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
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, RwLock, RwLockReadGuard,
    },
};

use dashmap::DashSet;
use log::debug;

use crate::{
    analysis::{ConstValue, SsaFunction, SsaOp, SsaVarId},
    compiler::{CompilerContext, EventKind, ModificationScope, SsaPass},
    deobfuscation::EmulationTemplatePool,
    emulation::{EmValue, EmulationProcess},
    metadata::token::Token,
    CilObject, Error, Result,
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
    /// Emulation process with initialized static state.
    /// Populated lazily on first `run_on_method()` call via pool fork + targeted warmup.
    /// Cleared in `finalize()` to release the assembly reference.
    process: RwLock<Option<EmulationProcess>>,
    /// Whether initialization has been attempted (success or failure).
    initialized: AtomicBool,
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
    /// Counter for reporting total removed predicates.
    removed_count: AtomicUsize,
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
            process: RwLock::new(None),
            initialized: AtomicBool::new(false),
            template_pool,
            needed_static_fields: needed,
            affected_methods: affected,
            processed_methods: DashSet::new(),
            removed_count: AtomicUsize::new(0),
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
    /// Uses double-checked locking via the `initialized` atomic flag. The first
    /// caller acquires a write lock, forks from the pool with targeted warmup,
    /// and sets the flag. Subsequent callers skip the write lock entirely.
    fn ensure_initialized(&self) -> RwLockReadGuard<'_, Option<EmulationProcess>> {
        if !self.initialized.load(Ordering::Acquire) {
            let mut guard = self.process.write().unwrap();
            if !self.initialized.load(Ordering::Relaxed) {
                *guard = self.create_process_from_pool();
                self.initialized.store(true, Ordering::Release);
            }
        }
        self.process.read().unwrap()
    }

    /// Resolves a static field -> instance field chain to a boolean value.
    ///
    /// Handles two cases:
    /// 1. Static field is a direct primitive (I32/I64/Bool) -- check CIL truthiness
    /// 2. Static field is an object reference -- read instance field from the
    ///    emulated heap and check CIL truthiness of the result
    ///
    /// For both static and instance field lookups, if the direct token lookup fails
    /// and the token is a MemberRef (table 0x0A), the function resolves it to the
    /// corresponding FieldDef token (table 0x04) and retries. This handles the common
    /// case where opaque predicate methods reference fields via MemberRef but the
    /// emulator stores values under FieldDef tokens from the initializer code.
    ///
    /// Returns `None` if the static field is not populated or if the instance
    /// field cannot be read from the heap.
    fn resolve_field_chain(
        process: &EmulationProcess,
        assembly: &CilObject,
        static_field_token: Token,
        instance_field_token: Token,
    ) -> Result<Option<bool>> {
        // Try direct static field lookup, then MemberRef→FieldDef fallback
        let static_val = match process.get_static(static_field_token)? {
            Some(val) => val,
            None => {
                let Some(resolved) = assembly.resolver().resolve_field(static_field_token) else {
                    return Ok(None);
                };
                match process.get_static(resolved)? {
                    Some(val) => val,
                    None => return Ok(None),
                }
            }
        };

        match static_val {
            // Direct primitive in static field
            EmValue::I32(_) | EmValue::I64(_) | EmValue::Bool(_) => {
                Ok(Some(static_val.to_bool_cil()))
            }
            // Object reference → read instance field from heap
            EmValue::ObjectRef(heap_ref) => {
                // Try direct instance field lookup, then MemberRef→FieldDef fallback
                let field_val = match process
                    .address_space()
                    .get_field(heap_ref, instance_field_token)
                {
                    Ok(val) => val,
                    Err(_) => {
                        let Some(resolved) =
                            assembly.resolver().resolve_field(instance_field_token)
                        else {
                            return Ok(None);
                        };
                        match process.address_space().get_field(heap_ref, resolved) {
                            Ok(val) => val,
                            Err(_) => return Ok(None),
                        }
                    }
                };
                Ok(Some(field_val.to_bool_cil()))
            }
            _ => Ok(None),
        }
    }

    /// Resolves a static field -> instance field chain to a [`ConstValue`].
    ///
    /// Same field lookup logic as [`resolve_field_chain`] but returns the raw
    /// constant value instead of a boolean. Used for field constant injection
    /// where `LoadField` instructions are replaced with `Const` instructions.
    ///
    /// Returns `None` if the field chain cannot be resolved or the value
    /// cannot be represented as a `ConstValue` (e.g., object references).
    fn resolve_field_value(
        process: &EmulationProcess,
        assembly: &CilObject,
        static_field_token: Token,
        instance_field_token: Token,
    ) -> Result<Option<ConstValue>> {
        // Try direct static field lookup, then MemberRef→FieldDef fallback
        let static_val = match process.get_static(static_field_token)? {
            Some(val) => val,
            None => {
                let Some(resolved) = assembly.resolver().resolve_field(static_field_token) else {
                    return Ok(None);
                };
                match process.get_static(resolved)? {
                    Some(val) => val,
                    None => return Ok(None),
                }
            }
        };

        match static_val {
            // Direct primitive in static field → convert to ConstValue
            EmValue::I32(_)
            | EmValue::I64(_)
            | EmValue::Bool(_)
            | EmValue::F32(_)
            | EmValue::F64(_) => Ok(static_val.to_const_value()),
            // Object reference → read instance field from heap
            EmValue::ObjectRef(heap_ref) => {
                let field_val = match process
                    .address_space()
                    .get_field(heap_ref, instance_field_token)
                {
                    Ok(val) => val,
                    Err(_) => {
                        let Some(resolved) =
                            assembly.resolver().resolve_field(instance_field_token)
                        else {
                            return Ok(None);
                        };
                        match process.address_space().get_field(heap_ref, resolved) {
                            Ok(val) => val,
                            Err(_) => return Ok(None),
                        }
                    }
                };
                Ok(field_val.to_const_value())
            }
            _ => Ok(None),
        }
    }

    /// Resolves a sentinel null-check field to a boolean value.
    ///
    /// The sentinel method pattern is `ceq(ldsfld(field), null)`, which returns
    /// `true` if the field value is null. For unset static fields, the ECMA-335
    /// default is null (reference types), so the result is `true`.
    ///
    /// Uses the same MemberRef → FieldDef fallback as `resolve_field_chain`.
    fn resolve_sentinel_field(
        process: &EmulationProcess,
        assembly: &CilObject,
        sentinel_field_token: Token,
    ) -> Result<Option<bool>> {
        let val = match process.get_static(sentinel_field_token)? {
            Some(val) => val,
            None => {
                // Try MemberRef → FieldDef fallback
                let Some(resolved) = assembly.resolver().resolve_field(sentinel_field_token) else {
                    // Field not found at all — default to null (never written)
                    return Ok(Some(true));
                };
                match process.get_static(resolved)? {
                    Some(val) => val,
                    // Not in emulator statics — reference type default is null
                    None => EmValue::Null,
                }
            }
        };
        // ceq(val, null): returns true if field is null
        Ok(Some(val.is_null()))
    }
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

    fn should_run(&self, method_token: Token, _ctx: &CompilerContext) -> bool {
        self.affected_methods.contains(&method_token)
            && !self.processed_methods.contains(&method_token)
    }

    fn initialize(&mut self, _ctx: &CompilerContext) -> Result<()> {
        let remaining = self.affected_methods.len() - self.processed_methods.len();
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
        let guard = self.ensure_initialized();
        let Some(process) = guard.as_ref() else {
            return Ok(false);
        };

        // Build def map: SsaVarId → defining SsaOp
        let mut defs: HashMap<SsaVarId, &SsaOp> = HashMap::new();
        for block in ssa.blocks() {
            for instr in block.instructions() {
                if let Some(dest) = instr.op().dest() {
                    defs.insert(dest, instr.op());
                }
            }
        }

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

            // --- Variant A: LoadStaticField → LoadField → Branch ---
            if let SsaOp::LoadField { object, field, .. } = cond_def {
                if let Some(SsaOp::LoadStaticField {
                    field: static_field,
                    ..
                }) = defs.get(object)
                {
                    if let Some(is_truthy) = Self::resolve_field_chain(
                        process,
                        assembly,
                        static_field.token(),
                        field.token(),
                    )? {
                        let (target, dropped) = if is_truthy {
                            (true_target, false_target)
                        } else {
                            (false_target, true_target)
                        };
                        replacements.push((block_idx, target, dropped));
                        continue;
                    }
                }
            }

            // --- Variant B: Call(sentinel_method) → Branch ---
            if let SsaOp::Call { method, .. } = cond_def {
                if let Some(sentinel_field) = self.sentinel_methods.get(&method.token()) {
                    if let Some(is_truthy) =
                        Self::resolve_sentinel_field(process, assembly, *sentinel_field)?
                    {
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
                    if let Some(is_truthy) =
                        Self::resolve_sentinel_field(process, assembly, *sentinel_field)?
                    {
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

        // --- Field constant injection: LoadField → Const ---
        let mut const_replacements: Vec<(usize, usize, SsaOp)> = Vec::new();
        let mut replaced_object_vars: HashSet<SsaVarId> = HashSet::new();

        for (block_idx, block) in ssa.blocks().iter().enumerate() {
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                let SsaOp::LoadField {
                    dest,
                    object,
                    field,
                } = instr.op()
                else {
                    continue;
                };

                // Trace object → LoadStaticField
                let Some(SsaOp::LoadStaticField {
                    field: static_field,
                    ..
                }) = defs.get(object)
                else {
                    continue;
                };

                // Try to resolve the field value from emulated state
                let Some(const_val) = Self::resolve_field_value(
                    process,
                    assembly,
                    static_field.token(),
                    field.token(),
                )?
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
        if changed {
            self.removed_count.fetch_add(
                replacements.len() + const_replacements.len() + sentinel_call_replacements.len(),
                Ordering::Relaxed,
            );
        }
        // Mark as processed to prevent redundant re-processing in subsequent
        // pipeline iterations. Even if no changes were made, the SSA was scanned
        // and won't yield different results with the same emulation state.
        self.processed_methods.insert(method_token);
        Ok(changed)
    }

    fn finalize(&mut self, _ctx: &CompilerContext) -> Result<()> {
        let count = self.removed_count.load(Ordering::Relaxed);
        if count > 0 {
            debug!("Opaque field predicate removal: replaced {count} predicates");
        }
        // Clear the emulation process to release its Arc<CilObject> reference.
        // This is needed so the assembly can be unwrapped for code generation.
        *self
            .process
            .write()
            .map_err(|e| Error::LockError(format!("opaque field process write lock: {e}")))? = None;
        Ok(())
    }
}
