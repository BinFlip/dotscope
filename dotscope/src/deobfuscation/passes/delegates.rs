//! Delegate proxy resolution pass.
//!
//! Resolves delegate-based call indirection by emulating delegate type
//! `.cctor`s to extract the actual target method bound to each delegate
//! singleton, then replacing indirect `Call(wrapper, ..., delegate)` with
//! direct `Call`/`CallVirt` to the resolved target.
//!
//! # Emulation Strategy
//!
//! The pass receives pre-computed findings from SSA-level detection
//! (`GenericDelegateProxy::detect_ssa`), which provides the exact set of
//! delegate types and affected methods. The pass then:
//!
//! 1. **Targeted warmup** (first `run_on_method`): Executes `.cctor`s for
//!    all detected delegate proxy types using fork-based isolation with
//!    multi-pass execution to handle dependency chains.
//!
//! 2. **Target extraction**: After warmup, reads each delegate singleton
//!    from the emulator's static fields, extracts the bound method token
//!    from the `HeapObject::Delegate` variant.
//!
//! 3. **SSA rewriting**: For each `Call(wrapper, args..., delegate)`,
//!    replaces with `Call(target, args...)` or `CallVirt(target, args...)`.
//!
//! # Safety
//!
//! If warmup fails or a delegate cannot be resolved, those call sites are
//! silently skipped — no false positives are possible.

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, RwLockReadGuard},
};

use dashmap::{DashMap, DashSet};
use log::debug;

use crate::{
    analysis::{CilTarget, MethodRef, MethodRef as SsaMethodRef, SsaFunction, SsaOp, SsaVarId},
    assembly::{FlowType, Instruction, Operand},
    compiler::{CompilerContext, EventKind, ModificationScope, SsaPass},
    deobfuscation::{utils::build_def_map, EmulationTemplatePool, ProcessCell},
    emulation::{tokens, EmValue, EmulationProcess, HeapObject},
    metadata::token::Token,
    CilObject, Result,
};

/// Information about a detected delegate proxy type.
#[derive(Debug, Clone)]
pub struct DelegateTypeInfo {
    /// Token of the static field holding the delegate singleton instance.
    pub singleton_field_token: Token,
    /// Token of the static wrapper method that forwards calls through the delegate.
    pub wrapper_method_token: Token,
}

/// Resolved target for a delegate proxy singleton.
#[derive(Debug, Clone)]
struct ResolvedTarget {
    /// The actual method token that the delegate calls.
    method_token: Token,
    /// Whether the call should use `CallVirt` (instance method) vs `Call` (static).
    is_virtual: bool,
}

/// Resolves delegate proxy call indirection via emulation.
///
/// This pass emulates delegate type `.cctor`s to populate singleton fields,
/// then reads the bound method from each delegate to replace indirect calls
/// with direct calls to the actual target.
///
/// The emulation process is cleared in `finalize()` to release its `Arc<CilObject>`
/// reference before code generation needs to unwrap the assembly.
pub struct DelegateProxyResolutionPass {
    /// Lazily-initialized emulation process (pool fork + targeted warmup).
    /// Cleared in `finalize()` to release the assembly reference.
    lazy_process: ProcessCell,
    /// Shared emulation template pool for O(1) forks with pre-warmed state.
    template_pool: Arc<EmulationTemplatePool>,
    /// delegate_type_token → DelegateTypeInfo from detection.
    delegate_types: HashMap<Token, DelegateTypeInfo>,
    /// wrapper_method_token → delegate_type_token (reverse index for SSA lookup).
    wrapper_to_delegate: HashMap<Token, Token>,
    /// delegate singleton field token → resolved target (method_token, is_virtual).
    resolved_targets: DashMap<Token, ResolvedTarget>,
    /// Method tokens that contain the delegate proxy pattern.
    affected_methods: DashSet<Token>,
    /// Methods already successfully processed. Prevents redundant re-processing
    /// across pipeline iterations when the same pass instance is reused.
    processed_methods: DashSet<Token>,
}

impl DelegateProxyResolutionPass {
    /// Creates a new delegate proxy resolution pass with pre-computed findings.
    ///
    /// The caller (typically `GenericDelegateProxy::create_pass()`) provides the
    /// exact set of delegate types and affected methods discovered during
    /// SSA-level detection.
    ///
    /// # Arguments
    ///
    /// * `template_pool` - Shared emulation template pool for O(1) forks.
    /// * `delegate_types` - Delegate type tokens mapped to their detection info.
    /// * `affected_methods` - Method tokens that contain delegate proxy calls.
    #[must_use]
    pub fn new(
        template_pool: Arc<EmulationTemplatePool>,
        delegate_types: HashMap<Token, DelegateTypeInfo>,
        affected_methods: HashSet<Token>,
    ) -> Self {
        let mut wrapper_to_delegate = HashMap::new();
        for (&type_token, info) in &delegate_types {
            wrapper_to_delegate.insert(info.wrapper_method_token, type_token);
        }

        let affected = DashSet::new();
        for token in &affected_methods {
            affected.insert(*token);
        }

        Self {
            lazy_process: ProcessCell::new("delegate proxy"),
            template_pool,
            delegate_types,
            wrapper_to_delegate,
            resolved_targets: DashMap::new(),
            affected_methods: affected,
            processed_methods: DashSet::new(),
        }
    }

    /// Finds `.cctor` tokens for all detected delegate proxy types.
    fn find_delegate_cctors(
        assembly: &CilObject,
        delegate_types: &HashMap<Token, DelegateTypeInfo>,
    ) -> Vec<Token> {
        let registry = assembly.types();
        let mut cctors = Vec::new();

        for &type_token in delegate_types.keys() {
            let Some(type_ref) = registry.get(&type_token) else {
                continue;
            };
            if let Some(cctor) = type_ref.cctor() {
                if !cctors.contains(&cctor) {
                    cctors.push(cctor);
                }
            }
        }

        cctors
    }

    /// Creates an emulation process by forking the shared template and running
    /// targeted warmup for delegate type `.cctor`s.
    ///
    /// The base template already has Module.cctor and registered warmup methods
    /// completed. This adds delegate-type-specific `.cctor` execution on top.
    fn create_process_from_pool(&self) -> Option<EmulationProcess> {
        let assembly = self.template_pool.assembly()?;
        let cctors = Self::find_delegate_cctors(&assembly, &self.delegate_types);
        let process = self.template_pool.fork_for_targeted_warmup(&cctors);
        if process.is_none() {
            log::warn!(
                "DelegateProxyResolution: failed to create emulation process — pass will be a no-op"
            );
        }
        process
    }

    /// Ensures the emulation process is initialized and targets are extracted.
    ///
    /// Delegates to [`ProcessCell::ensure_initialized`] with a fork +
    /// targeted warmup closure and a post-init callback that extracts delegate
    /// targets from the emulated state.
    fn ensure_initialized(&self) -> Result<RwLockReadGuard<'_, Option<EmulationProcess>>> {
        self.lazy_process.ensure_initialized(
            || self.create_process_from_pool(),
            |process| self.extract_targets(process),
        )
    }

    /// Extracts delegate targets from the emulated static state.
    ///
    /// For each delegate type, reads the singleton field, checks if it's an
    /// `ObjectRef` pointing to a `HeapObject::Delegate`, and stores the
    /// bound method token in `resolved_targets`.
    fn extract_targets(&self, process: &EmulationProcess) {
        let assembly = self.template_pool.assembly();

        for info in self.delegate_types.values() {
            let field_token = info.singleton_field_token;

            // Try direct static field lookup, then MemberRef→FieldDef fallback.
            // Errors from get_static are lock poisoning — skip this field on failure.
            let Ok(static_val_direct) = process.get_static(field_token) else {
                continue;
            };
            let static_val = static_val_direct.or_else(|| {
                let asm = assembly.as_ref()?;
                let resolved = asm.resolver().resolve_field(field_token)?;
                process.get_static(resolved).ok().flatten()
            });

            let Some(EmValue::ObjectRef(heap_ref)) = static_val else {
                continue;
            };

            // Read the heap object to extract the delegate binding
            let Ok(obj) = process.address_space().heap().get(heap_ref) else {
                continue;
            };

            if let HeapObject::Delegate {
                invocation_list, ..
            } = obj
            {
                if let Some(entry) = invocation_list.last() {
                    let method_token = entry.method_token;

                    // Resolve synthetic DynamicMethod tokens to real metadata tokens.
                    // DynamicMethod bodies are usually simple wrappers (ldarg*; call; ret).
                    let (resolved_token, synthetic_is_virtual): (Token, Option<bool>) =
                        if tokens::is_synthetic_method(method_token) {
                            let synthetic_methods =
                                process.thread_context().synthetic_methods.clone();
                            let mut current = method_token;
                            let mut result = None;
                            let mut visited = HashSet::new();
                            // Follow chains (synthetic → synthetic → real) with cycle detection
                            loop {
                                if !visited.insert(current) {
                                    // Cycle detected — stop traversal
                                    break;
                                }
                                if let Some(body) = synthetic_methods.get(&current) {
                                    if let Some((real_token, is_virt)) =
                                        resolve_synthetic_target(&body.instructions)
                                    {
                                        if tokens::is_synthetic_method(real_token) {
                                            current = real_token;
                                            continue;
                                        }
                                        result = Some((real_token, is_virt));
                                    }
                                }
                                break;
                            }
                            match result {
                                Some((token, is_virt)) => (token, Some(is_virt)),
                                None => {
                                    debug!(
                                        "Skipping unresolvable synthetic delegate 0x{:08X}",
                                        method_token.value()
                                    );
                                    continue;
                                }
                            }
                        } else {
                            (method_token, None)
                        };

                    // Determine is_virtual: prefer info from synthetic wrapper opcode,
                    // fall back to assembly metadata lookup
                    let is_virtual = synthetic_is_virtual.unwrap_or_else(|| {
                        assembly
                            .as_ref()
                            .and_then(|asm| asm.method(&resolved_token))
                            .map(|m| !m.is_static())
                            .unwrap_or(false)
                    });

                    self.resolved_targets.insert(
                        field_token,
                        ResolvedTarget {
                            method_token: resolved_token,
                            is_virtual,
                        },
                    );
                }
            }
        }

        debug!(
            "Delegate proxy resolution: resolved {}/{} delegate targets",
            self.resolved_targets.len(),
            self.delegate_types.len()
        );
    }
}

/// Resolves a delegate argument variable to its `LoadStaticField` field token.
///
/// Follows one level of `Copy` or `Phi` indirection to handle cases where the
/// delegate singleton passes through SSA variable merging before reaching the
/// call site.
///
/// For phi nodes, all operands must resolve to `LoadStaticField` of the **same**
/// field token — if different fields merge at a phi, the delegate target is
/// ambiguous and resolution returns `None`.
///
/// # Arguments
///
/// * `var` - The SSA variable used as the delegate argument.
/// * `defs` - Map from SSA variable ID to its defining operation.
/// * `ssa` - The SSA function, for phi node lookups.
///
/// # Returns
///
/// The singleton field token if resolution succeeds, `None` if the variable
/// doesn't trace back to a single consistent `LoadStaticField`.
fn resolve_delegate_field(
    var: SsaVarId,
    defs: &HashMap<SsaVarId, &SsaOp>,
    ssa: &SsaFunction,
) -> Option<Token> {
    // Direct: LoadStaticField
    if let Some(SsaOp::LoadStaticField { field, .. }) = defs.get(&var) {
        return Some(field.token());
    }

    // Copy indirection: Copy { src } → recurse on src
    if let Some(SsaOp::Copy { src, .. }) = defs.get(&var) {
        if let Some(SsaOp::LoadStaticField { field, .. }) = defs.get(src) {
            return Some(field.token());
        }
    }

    // Phi indirection: all operands must resolve to the same LoadStaticField
    for block in ssa.blocks() {
        for phi in block.phi_nodes() {
            if phi.result() != var {
                continue;
            }
            let mut common_token: Option<Token> = None;
            for operand in phi.operands() {
                let operand_token = match defs.get(&operand.value()) {
                    Some(SsaOp::LoadStaticField { field, .. }) => field.token(),
                    // Operand is a Copy → follow one more level
                    Some(SsaOp::Copy { src, .. }) => match defs.get(src) {
                        Some(SsaOp::LoadStaticField { field, .. }) => field.token(),
                        _ => return None,
                    },
                    _ => return None,
                };
                match common_token {
                    None => common_token = Some(operand_token),
                    Some(t) if t == operand_token => {}
                    Some(_) => return None, // Different fields → ambiguous
                }
            }
            return common_token;
        }
    }

    None
}

/// Inspects a synthetic method's IL to extract the real method token it wraps.
///
/// Detects the simple wrapper pattern: `ldarg*; [tail.] call/callvirt Token; ret`
/// Returns `(real_token, is_callvirt)` if the pattern matches.
fn resolve_synthetic_target(instructions: &[Instruction]) -> Option<(Token, bool)> {
    // Filter out nop and prefix instructions for analysis
    let meaningful: Vec<&Instruction> = instructions
        .iter()
        .filter(|i| i.mnemonic != "nop")
        .collect();

    if meaningful.is_empty() {
        return None;
    }

    // Last meaningful instruction must be ret
    let last = meaningful.last()?;
    if last.flow_type != FlowType::Return {
        return None;
    }

    // Find the single call/callvirt instruction
    let mut call_token = None;
    let mut is_callvirt = false;

    for instr in &meaningful {
        match instr.mnemonic {
            "call" | "callvirt" => {
                if call_token.is_some() {
                    // Multiple calls — not a simple wrapper
                    return None;
                }
                if let Operand::Token(token) = &instr.operand {
                    call_token = Some(*token);
                    is_callvirt = instr.mnemonic == "callvirt";
                } else {
                    return None;
                }
            }
            // tail. prefix is allowed before call/callvirt
            "tail." => {}
            // ret is handled above
            "ret" => {}
            // ldarg variants are expected
            m if m.starts_with("ldarg") => {}
            // Anything else means this isn't a simple wrapper
            _ => return None,
        }
    }

    call_token.map(|token| (token, is_callvirt))
}

impl SsaPass<CilTarget, CompilerContext> for DelegateProxyResolutionPass {
    fn name(&self) -> &'static str {
        "delegate-proxy-resolution"
    }

    fn description(&self) -> &'static str {
        "Resolves delegate proxy calls to direct method calls via emulation"
    }

    fn modification_scope(&self) -> ModificationScope {
        ModificationScope::InstructionsOnly
    }

    fn should_run(&self, method: &MethodRef, _host: &CompilerContext) -> bool {
        self.affected_methods.contains(&method.0) && !self.processed_methods.contains(&method.0)
    }

    fn initialize(&mut self, _host: &CompilerContext) -> analyssa::Result<()> {
        let remaining = self
            .affected_methods
            .len()
            .saturating_sub(self.processed_methods.len());
        if remaining > 0 {
            debug!(
                "Delegate proxy resolution: {} delegate types, {} remaining methods ({} already processed)",
                self.delegate_types.len(),
                remaining,
                self.processed_methods.len(),
            );
        }
        Ok(())
    }

    fn run_on_method(
        &self,
        ssa: &mut SsaFunction,
        method: &MethodRef,
        host: &CompilerContext,
    ) -> analyssa::Result<bool> {
        let ctx = host;
        let method_token = method.0;
        let guard = self.ensure_initialized()?;
        let Some(_process) = guard.as_ref() else {
            return Ok(false);
        };

        // Build def map: SsaVarId → defining SsaOp
        let defs = build_def_map(ssa);

        // Find delegate proxy calls and collect replacements.
        // Each replacement: (block_idx, instr_idx, new_op)
        let mut replacements: Vec<(usize, usize, SsaOp)> = Vec::new();
        // Track LoadStaticField instructions to NOP: (block_idx, instr_idx).
        // These loaded the delegate singleton that is no longer needed after
        // the Call is rewritten. Without this, the dead LoadStaticField produces
        // a dead local variable typed to the delegate class, which prevents the
        // cleanup pipeline from removing the now-empty delegate type.
        let mut dead_loads: Vec<(usize, usize)> = Vec::new();
        // Track which delegate vars we plan to remove, so we only NOP a
        // LoadStaticField if ALL its consumers are being replaced.
        let mut removed_delegate_vars: HashSet<SsaVarId> = HashSet::new();

        for (block_idx, block) in ssa.blocks().iter().enumerate() {
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                let SsaOp::Call { method, args, dest } = instr.op() else {
                    continue;
                };

                // Check if this Call targets a known wrapper method
                let Some(&_delegate_type_token) = self.wrapper_to_delegate.get(&method.token())
                else {
                    continue;
                };

                // The last argument should be the delegate instance loaded from
                // a static field. Trace it back through phis/copies to LoadStaticField.
                let Some(&delegate_var) = args.last() else {
                    continue;
                };

                let Some(singleton_field_token) = resolve_delegate_field(delegate_var, &defs, ssa)
                else {
                    continue;
                };

                // Look up the resolved target for this singleton field
                let target = self
                    .resolved_targets
                    .get(&singleton_field_token)
                    .or_else(|| {
                        let asm = self.template_pool.assembly()?;
                        let resolved = asm.resolver().resolve_field(singleton_field_token)?;
                        self.resolved_targets.get(&resolved)
                    });

                let Some(target_entry) = target else {
                    continue;
                };

                // Build the replacement: drop the last arg (delegate instance)
                let drop_to = args.len().saturating_sub(1);
                let new_args: Vec<SsaVarId> = args
                    .get(..drop_to)
                    .map(<[SsaVarId]>::to_vec)
                    .unwrap_or_default();
                let target_method = SsaMethodRef::new(target_entry.method_token);

                let new_op = if target_entry.is_virtual {
                    SsaOp::CallVirt {
                        dest: *dest,
                        method: target_method,
                        args: new_args,
                    }
                } else {
                    SsaOp::Call {
                        dest: *dest,
                        method: target_method,
                        args: new_args,
                    }
                };

                replacements.push((block_idx, instr_idx, new_op));
                removed_delegate_vars.insert(delegate_var);
            }
        }

        // Find LoadStaticField instructions whose dest is only used by the
        // delegate proxy calls we're replacing. These can be safely NOP'd.
        for (block_idx, block) in ssa.blocks().iter().enumerate() {
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                let SsaOp::LoadStaticField { dest, .. } = instr.op() else {
                    continue;
                };
                if !removed_delegate_vars.contains(dest) {
                    continue;
                }
                // Check that this variable has no other uses beyond the delegate
                // proxy calls we're replacing. If the variable is used elsewhere,
                // we must keep the LoadStaticField.
                if let Some(variable) = ssa.variable(*dest) {
                    let all_uses_removed = variable.uses().iter().all(|use_site| {
                        replacements
                            .iter()
                            .any(|(b, i, _)| *b == use_site.block && *i == use_site.instruction)
                    });
                    if all_uses_removed {
                        dead_loads.push((block_idx, instr_idx));
                    }
                }
            }
        }

        // Must drop the read guard before mutating ssa
        drop(guard);

        // Apply call replacements
        for (block_idx, instr_idx, new_op) in &replacements {
            if let Some(block) = ssa.block_mut(*block_idx) {
                if let Some(instr) = block.instructions_mut().get_mut(*instr_idx) {
                    let target_desc = match new_op {
                        SsaOp::Call { method, .. } => {
                            format!("call 0x{:08X}", method.token().value())
                        }
                        SsaOp::CallVirt { method, .. } => {
                            format!("callvirt 0x{:08X}", method.token().value())
                        }
                        _ => "unknown".to_string(),
                    };
                    instr.set_op(new_op.clone());
                    ctx.events
                        .record(EventKind::MethodInlined)
                        .at(method_token, *block_idx)
                        .message(format!("resolved delegate proxy → {target_desc}"));
                }
            }
        }

        // NOP out dead LoadStaticField instructions that loaded delegate singletons
        for (block_idx, instr_idx) in &dead_loads {
            if let Some(block) = ssa.block_mut(*block_idx) {
                if let Some(instr) = block.instructions_mut().get_mut(*instr_idx) {
                    instr.set_op(SsaOp::Nop);
                }
            }
        }

        let changed = !replacements.is_empty();
        // Mark as processed to prevent redundant re-processing in subsequent
        // pipeline iterations. The delegate targets are frozen after emulation
        // initialization, so re-scanning the same method yields identical results.
        self.processed_methods.insert(method_token);
        Ok(changed)
    }

    fn finalize(&mut self, _host: &CompilerContext) -> analyssa::Result<()> {
        // Clear the emulation process to release its Arc<CilObject> reference.
        self.lazy_process.clear().map_err(Into::into)
    }
}
