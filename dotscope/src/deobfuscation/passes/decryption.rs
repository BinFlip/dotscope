//! Decryption pass for obfuscated values.
//!
//! This pass decrypts obfuscated constants and strings by emulating calls to
//! registered decryptor methods. The [`DecryptorContext`] is populated during
//! the detection phase by:
//!
//! - **Obfuscator-specific detectors** (ConfuserEx, etc.) with high confidence
//! - **Heuristic detectors** that identify potential decryptors by signature
//!
//! # Flow
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                        Decryption Flow                              │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │                                                                     │
//! │  1. Detection Phase                                                 │
//! │     ├─> Obfuscator detector: ctx.decryptors.register(token, info)  │
//! │     └─> Heuristic detector: ctx.decryptors.register(token, info)   │
//! │                                                                     │
//! │  2. DecryptionPass (this pass)                                     │
//! │     For each call instruction:                                     │
//! │     └─> Check if target is a registered decryptor                  │
//! │     └─> Get constant arguments from known_values                   │
//! │     └─> Check cache for previous emulation result                  │
//! │     └─> Emulate the decryptor method                               │
//! │     └─> Replace call with constant value                           │
//! │     └─> Record success/failure in DecryptorContext                 │
//! │                                                                     │
//! │  3. Cleanup (obfuscator postprocess)                               │
//! │     └─> Remove decryptor methods where all calls were handled      │
//! │                                                                     │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! Before (obfuscated constant):
//! ```text
//! v0 = call DecryptorModule::Get<int32>(12345)
//! v1 = add v0, 100
//! ```
//!
//! After:
//! ```text
//! v0 = 42
//! v1 = add v0, 100
//! ```
//!
//! Before (obfuscated string):
//! ```text
//! v0 = call StringDecryptor::Decrypt(98765)
//! call Console::WriteLine(v0)
//! ```
//!
//! After:
//! ```text
//! v0 = "Hello, World!"
//! call Console::WriteLine(v0)
//! ```

use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};

use rayon::prelude::*;

use crate::{
    analysis::{ConstValue, SsaCfg, SsaFunction, SsaOp, SsaVarId, ValueResolver},
    compiler::{CompilerContext, EventKind, EventLog, ModificationScope, PassCapability, SsaPass},
    deobfuscation::{
        context::AnalysisContext,
        decryptors::{DecryptorContext, FailureReason},
        CfgInfo, EmulationTemplatePool, StateMachineProvider, StateMachineState, StateUpdateCall,
    },
    emulation::{
        EmValue, EmulationError, EmulationOutcome, EmulationProcess, EmulationThread, StepResult,
    },
    metadata::{
        tables::TypeRefRaw,
        token::Token,
        typesystem::{CilFlavor, CilPrimitive, CilPrimitiveKind, PointerSize},
    },
    utils::graph::{
        algorithms::{compute_dominators, DominatorTree},
        GraphBase, NodeId, RootedGraph,
    },
    CilObject, Error, Result,
};

/// Decryption pass for obfuscated constants and strings.
///
/// This pass finds calls to registered decryptor methods and attempts to
/// evaluate them through emulation, replacing call sites with the decrypted
/// values (constants, strings, or other types).
///
/// It works in tandem with the [`DecryptorContext`](crate::deobfuscation::DecryptorContext)
/// which is populated during the detection phase by obfuscator-specific and
/// heuristic detectors.
///
/// # Emulation Template
///
/// The pass uses the shared [`EmulationTemplatePool`] for O(1) CoW forks.
/// The pool is warmed up once during engine initialization; this pass simply
/// calls [`EmulationTemplatePool::fork()`] for each decryption attempt.
///
/// If the pool is unavailable (no techniques registered emulation hooks),
/// decryption is silently skipped.
pub struct DecryptionPass {
    /// Shared emulation template pool for O(1) forks.
    ///
    /// `None` when no techniques registered emulation requirements.
    /// Each decryption call forks the pool's warmed template.
    template_pool: Option<Arc<EmulationTemplatePool>>,

    /// Decryptor tracking context (shared with AnalysisContext).
    decryptors: Arc<DecryptorContext>,
    /// State machine providers for order-dependent decryption.
    statemachine_providers: Arc<boxcar::Vec<Arc<dyn StateMachineProvider>>>,
    /// Maximum instructions per emulation call.
    emulation_max_instructions: u64,
}

/// Owned CFG analysis info, storing dominator tree and predecessors.
///
/// This is an internal struct used by `DecryptionPass` to hold CFG analysis
/// data that can be borrowed as a `CfgInfo` reference.
struct CfgInfoOwned {
    dom_tree: DominatorTree,
    predecessors: Vec<Vec<usize>>,
    node_count: usize,
    entry: NodeId,
}

impl CfgInfoOwned {
    /// Borrows this owned info as a `CfgInfo` reference.
    fn as_ref(&self) -> CfgInfo<'_> {
        CfgInfo {
            dom_tree: &self.dom_tree,
            predecessors: &self.predecessors,
            node_count: self.node_count,
            entry: self.entry,
        }
    }
}

impl DecryptionPass {
    /// Creates a new constant decryption pass from an analysis context.
    ///
    /// Captures shared references to the context's decryptors and state machine
    /// providers. Emulation is backed by the shared [`EmulationTemplatePool`]
    /// stored in the context (if available).
    ///
    /// # Arguments
    ///
    /// * `ctx` - The analysis context providing registered decryptors, state
    ///   machine providers, configuration, and the shared template pool.
    ///
    /// # Returns
    ///
    /// A new `DecryptionPass` ready for pipeline execution.
    #[must_use]
    pub fn new(ctx: &AnalysisContext) -> Self {
        Self {
            template_pool: ctx.template_pool.get().cloned(),
            decryptors: Arc::clone(&ctx.decryptors),
            statemachine_providers: Arc::clone(&ctx.statemachine_providers),
            emulation_max_instructions: ctx.config.emulation.max_instructions,
        }
    }

    /// Finds the state machine provider that applies to a method.
    fn get_statemachine_provider_for_method(
        &self,
        method: Token,
    ) -> Option<Arc<dyn StateMachineProvider>> {
        for (_, provider) in self.statemachine_providers.iter() {
            if provider.applies_to_method(method) {
                return Some(Arc::clone(provider));
            }
        }
        None
    }

    /// Forks the shared emulation template for a decryption call.
    ///
    /// Returns an O(1) CoW copy of the pre-warmed template from the
    /// [`EmulationTemplatePool`]. Returns an error if no pool is available
    /// or if warmup previously failed.
    fn fork_template_process(&self) -> Result<EmulationProcess> {
        match &self.template_pool {
            Some(pool) => pool.fork(),
            None => Err(Error::Emulation(Box::new(EmulationError::InternalError {
                description: "no emulation template available".to_string(),
            }))),
        }
    }

    /// Tries to decrypt a constant at a specific call site.
    ///
    /// Checks the DecryptorContext cache first, then attempts emulation.
    ///
    /// # Arguments
    ///
    /// * `decryptor` - The resolved decryptor MethodDef token.
    /// * `args` - The constant argument values.
    ///
    /// # Returns
    ///
    /// The decrypted value if successful, `None` otherwise along with an
    /// optional failure reason.
    fn try_decrypt_at_call(
        &self,
        decryptor: Token,
        call_target: Token,
        args: &[ConstValue],
    ) -> (Option<ConstValue>, Option<FailureReason>) {
        if let Some(cached) = self
            .decryptors
            .with_cached(decryptor, args, ConstValue::clone)
        {
            return (Some(cached), None);
        }

        // Use the original call target (which may be a MethodSpec) for emulation
        // so that generic type arguments are preserved for ldtoken resolution.
        let (result, failure) = self.emulate_call(call_target, args);

        if let Some(ref value) = result {
            self.decryptors.cache_value(decryptor, args, value.clone());
        }

        (result, failure)
    }

    /// Emulates a call to get the decrypted constant.
    ///
    /// Uses Copy-on-Write fork semantics for efficient emulation. A template
    /// process is created once (expensive: PE loading, mapping, hooks) and stored
    /// in the pass. Each call forks the template in O(1) time via structural
    /// sharing, with fresh mutable state for independent execution.
    ///
    /// # Arguments
    ///
    /// * `method` - The method token to emulate (may be MethodSpec for generics).
    /// * `args` - The constant arguments to pass.
    ///
    /// # Returns
    ///
    /// A tuple of (result, failure_reason).
    fn emulate_call(
        &self,
        method: Token,
        args: &[ConstValue],
    ) -> (Option<ConstValue>, Option<FailureReason>) {
        // Fork from the template process - O(1) due to CoW semantics.
        // The template is created lazily on first call with expensive PE loading,
        // hooks, etc. Subsequent calls share memory via structural sharing.
        let process = match self.fork_template_process() {
            Ok(p) => p,
            Err(e) => {
                return (None, Some(FailureReason::EmulationFailed(e.to_string())));
            }
        };

        // Convert ConstValue arguments to EmValue.
        // ConstValue::String holds a #US heap offset — resolve it to an actual
        // string from the assembly's UserStrings heap and allocate on the
        // emulation heap so the decryptor receives a proper ObjectRef.
        let em_args: Vec<EmValue> = args
            .iter()
            .map(|cv| match cv {
                ConstValue::String(us_offset) => {
                    let resolved = process.assembly().and_then(|asm| {
                        let us = asm.userstrings()?;
                        let u16str = us.get(*us_offset as usize).ok()?;
                        let s = u16str.to_string_lossy();
                        let href = process.address_space().alloc_string(&s).ok()?;
                        Some(EmValue::ObjectRef(href))
                    });
                    resolved.unwrap_or_else(|| EmValue::from(cv))
                }
                _ => EmValue::from(cv),
            })
            .collect();

        // Use thread-safe container to capture the return value
        let captured_value: Arc<Mutex<Option<ConstValue>>> = Arc::new(Mutex::new(None));
        let captured_clone = captured_value.clone();

        // Use emulate_until to stop when we see a return from the TARGET method.
        // IMPORTANT: Only capture returns at call_depth == 1 (the outermost method).
        // The condition fires for every `ret` instruction including nested calls.
        // Without this check, we'd capture the return value from the first inner
        // method call (e.g., the native x86 helper returning I32) instead of the
        // actual decryptor result (e.g., a DecryptedString).
        let outcome = match process.emulate_until(
            method,
            em_args,
            move |step_result: &StepResult, thread: &EmulationThread| {
                match step_result {
                    StepResult::Return { .. } => {
                        // Only capture returns from the outermost (target) method.
                        // call_depth == 1 means only the target method is on the stack.
                        if thread.call_depth() != 1 {
                            return false;
                        }
                        // Method is returning - the return value is on the stack
                        // (the StepResult::Return { value } field is always None for ret instructions)
                        if let Ok(em_value) = thread.stack().peek() {
                            let const_value = Self::emvalue_to_constvalue(em_value, thread);
                            if const_value.is_some() {
                                if let Ok(mut guard) = captured_clone.lock() {
                                    *guard = const_value;
                                }
                                return true; // Stop - we have a valid return value
                            }
                        }
                        false
                    }
                    _ => false,
                }
            },
        ) {
            Ok(o) => o,
            Err(e) => {
                return (None, Some(FailureReason::EmulationFailed(format!("{e}"))));
            }
        };

        // Extract the captured value
        match &outcome {
            EmulationOutcome::Stopped { .. } | EmulationOutcome::Completed { .. } => {
                let result = captured_value.lock().ok().and_then(|guard| guard.clone());
                if result.is_some() {
                    (result, None)
                } else {
                    (None, Some(FailureReason::InvalidReturnValue))
                }
            }
            EmulationOutcome::UnhandledException { exception, .. } => (
                None,
                Some(FailureReason::EmulationFailed(format!(
                    "unhandled exception: {exception:?}"
                ))),
            ),
            EmulationOutcome::LimitReached { limit, .. } => (
                None,
                Some(FailureReason::EmulationFailed(format!(
                    "limit reached: {limit:?}"
                ))),
            ),
            EmulationOutcome::RequiresSymbolic { reason, .. } => (
                None,
                Some(FailureReason::EmulationFailed(format!(
                    "requires symbolic: {reason}"
                ))),
            ),
            EmulationOutcome::Breakpoint { .. } => {
                // Breakpoint hit - try to get the captured value anyway
                let result = captured_value.lock().ok().and_then(|guard| guard.clone());
                if result.is_some() {
                    (result, None)
                } else {
                    (
                        None,
                        Some(FailureReason::EmulationFailed("breakpoint".to_string())),
                    )
                }
            }
        }
    }

    /// Resolves a `CilFlavor` to a real TypeRef/TypeDef token using the assembly's
    /// type registry and the existing `CilPrimitiveData::clr_full_name()` mapping.
    /// Resolves a `CilFlavor` to a real TypeRef token from the assembly's metadata.
    ///
    /// Searches the TypeRef table for the .NET type name matching the flavor
    /// (e.g., `U1` → TypeRef for `System.Byte`). Returns `None` if the assembly
    /// doesn't reference this type.
    fn resolve_flavor_to_typeref(flavor: &CilFlavor, thread: &EmulationThread) -> Option<Token> {
        let kind = CilPrimitiveKind::try_from(flavor.clone()).ok()?;
        let primitive = CilPrimitive::new(kind);
        let namespace = primitive.namespace();
        let name = primitive.name();

        let asm = thread.assembly()?;
        let tables = asm.tables()?;
        let strings = asm.strings()?;
        let type_refs = tables.table::<TypeRefRaw>()?;

        for row in type_refs {
            let row_name = strings.get(row.type_name as usize).ok()?;
            let row_ns = strings.get(row.type_namespace as usize).ok()?;
            if row_name == name && row_ns == namespace {
                return Some(row.token);
            }
        }
        None
    }

    /// Converts an EmValue to a ConstValue for decryption purposes.
    ///
    /// Handles primitive types via [`EmValue::to_const_value`] and additionally
    /// supports string objects by reading them from the emulation heap.
    ///
    /// **IMPORTANT**: Unlike `EmValue::to_const_value()`, this function rejects
    /// `Null` values. In a decryption context, null means the decryption failed
    /// (e.g., wrong key leading to out-of-bounds array access). Accepting null
    /// would silence actual decryption failures.
    fn emvalue_to_constvalue(em_value: &EmValue, thread: &EmulationThread) -> Option<ConstValue> {
        // Reject Null — typically means decryption failed (wrong key, OOB access, etc.).
        // Some decryptors may legitimately return null for conditional paths; if this
        // becomes an issue, the caller should distinguish emulation-error from returned-null.
        if matches!(em_value, EmValue::Null) {
            log::debug!("Decryption: emulation returned Null — treating as failure");
            return None;
        }

        // First try the basic conversion for primitives
        if let Some(cv) = em_value.to_const_value() {
            return Some(cv);
        }

        // Handle ObjectRef specially - try string, unbox, or array from heap
        if let EmValue::ObjectRef(href) = em_value {
            if let Ok(s) = thread.heap().get_string(*href) {
                return Some(ConstValue::DecryptedString(s.to_string()));
            }
            // Try to unbox a boxed primitive value from the heap
            if let Ok(unboxed) = thread.heap().unbox(*href) {
                if let Some(cv) = unboxed.to_const_value() {
                    return Some(cv);
                }
            }
            // Try to extract array data as bytes
            if let Ok(Some(bytes)) = thread.heap().get_array_as_bytes(*href, PointerSize::Bit32) {
                if let Ok(elem_flavor) = thread.heap().get_array_element_type(*href) {
                    let elem_size = elem_flavor.byte_size(PointerSize::Bit32).unwrap_or(1);
                    // Resolve the element CilFlavor to a real TypeRef token from the assembly
                    if let Some(token) = Self::resolve_flavor_to_typeref(&elem_flavor, thread) {
                        return Some(ConstValue::DecryptedArray {
                            data: bytes,
                            element_type_token: token,
                            element_size: elem_size,
                        });
                    }
                }
            }
        }

        // Handle ValueType with TypeSpec token - this happens with generic methods
        // where the return type is a type parameter. Try to extract the actual value.
        if let EmValue::ValueType { fields, .. } = em_value {
            // If the ValueType has a single field that's an ObjectRef, try to get string from it
            if fields.len() == 1 {
                if let EmValue::ObjectRef(href) = &fields[0] {
                    if let Ok(s) = thread.heap().get_string(*href) {
                        return Some(ConstValue::DecryptedString(s.to_string()));
                    }
                }
                // Try primitive conversion on the single field (but not if it's Null)
                if !matches!(fields[0], EmValue::Null) {
                    if let Some(cv) = fields[0].to_const_value() {
                        return Some(cv);
                    }
                }
            }
        }

        None
    }

    /// Gets constant values for call arguments using the [`ValueResolver`].
    ///
    /// This function supports PHI-aware tracing: if an argument is defined by
    /// a PHI node where all operands resolve to the same constant, that constant
    /// is returned. This is essential for handling control flow flattening where
    /// constants flow through PHI nodes before reaching decryptor calls.
    ///
    /// # Arguments
    ///
    /// * `args` - The SSA variable IDs of the arguments.
    /// * `resolver` - The value resolver pre-loaded with known values.
    ///
    /// # Returns
    ///
    /// A vector of constant values if all arguments resolve to constants, `None` otherwise.
    fn get_arg_constants(
        args: &[SsaVarId],
        resolver: &mut ValueResolver<'_>,
    ) -> Option<Vec<ConstValue>> {
        resolver.resolve_all(args)
    }

    /// Processes CFG mode decryption for a method using dominator-based path analysis.
    ///
    /// CFG mode encryption uses a state machine (CFGCtx) where each `Next()` call
    /// updates the state. The challenge is that different execution paths may have
    /// different sequences of `Next()` calls, so we can't just simulate them all
    /// linearly.
    ///
    /// # Algorithm
    ///
    /// For each decryptor call:
    /// 1. Find the `Next()` call that feeds its XOR operand
    /// 2. Build the dominator tree to find which blocks are guaranteed to execute
    ///    before the decryptor on ALL paths
    /// 3. Simulate only the `Next()` calls in dominating blocks (these are guaranteed
    ///    to have executed) plus same-block calls that precede the decryptor
    /// 4. Use the resulting state to compute the decryption key
    ///
    /// This is correct because:
    /// - A `Next()` call in a dominating block executes on ALL paths to the decryptor
    /// - A `Next()` call in the same block before the decryptor always executes first
    /// - `Next()` calls in non-dominating blocks are path-specific and may not execute
    ///
    /// # CFG Mode Pattern
    ///
    /// ```text
    /// v1 = const FLAG
    /// v2 = const INCREMENT
    /// v3 = call CFGCtx.Next(&ctx, v1, v2)   ; returns state value
    /// v4 = const ENCODED
    /// v5 = xor v3, v4                       ; actual_key = state_value ^ encoded
    /// v6 = call Decryptor(v5)
    /// ```
    ///
    /// The processing is delegated to the state machine provider, which implements
    /// obfuscator-specific logic for finding call sites and collecting relevant
    /// state updates.
    fn process_state_machine_mode(
        &self,
        ssa: &mut SsaFunction,
        method_token: Token,
        ctx: &CompilerContext,
        assembly: &CilObject,
        provider: &dyn StateMachineProvider,
        ptr_size: PointerSize,
    ) -> (bool, EventLog) {
        let changes = EventLog::new();

        // Clone semantics into Arc for StateMachineState
        let semantics = Arc::new(provider.semantics().clone());

        // Find all state update calls using the provider
        let state_updates = provider.find_state_updates(ssa);
        if state_updates.is_empty() {
            return (false, changes);
        }

        // Build CFG info for path-sensitive analysis
        let cfg_info = Self::build_cfg_info(ssa);

        // Find decryptor call sites using the provider's pattern matching.
        // Use all_resolvable_tokens() to include MethodSpec tokens that map to
        // registered decryptors via MemberRef — these are needed for generic
        // instantiations like Get<int32>() that may use MemberRef indirection.
        let decryptor_tokens = self.decryptors.all_resolvable_tokens();
        let call_sites =
            provider.find_decryptor_call_sites(ssa, &state_updates, &decryptor_tokens, assembly);

        if call_sites.is_empty() {
            return (false, changes);
        }

        // Find ALL state machine seeds in the method using the provider
        let all_seeds = provider.find_initializations(ssa, ctx, method_token, assembly);

        let mut changed = false;
        let mut failures: Vec<(Token, usize, FailureReason)> = Vec::new();

        // Process each decryptor call independently with its own state machine
        for call_site in &call_sites {
            let location = call_site.location();

            if self.decryptors.is_already_decrypted(method_token, location) {
                continue;
            }
            if self
                .decryptors
                .has_permanent_failure(method_token, location)
            {
                continue;
            }

            // Find the correct seed for this call site using the provider
            let seed = provider
                .find_seed_for_call(&all_seeds, call_site, &cfg_info.as_ref())
                .unwrap_or(0);

            // Initialize fresh state machine from seed
            let mut state = StateMachineState::from_seed_u32(seed, Arc::clone(&semantics));

            // Find the seed's block location for filtering.
            let seed_block = all_seeds
                .iter()
                .filter(|(_, _, val)| *val == seed)
                .map(|(block, _, _)| *block)
                .min();

            // Collect relevant updates using the provider's BFS path algorithm.
            // Seed-block filtering is now done inside collect_updates_for_call
            // using path position (not block index) for correct execution ordering.
            let relevant_updates = provider.collect_updates_for_call(
                call_site,
                &state_updates,
                &cfg_info.as_ref(),
                seed_block,
            );

            // Construct ValueResolver for this iteration (reborrow ssa as shared)
            let mut resolver = ValueResolver::new(&*ssa, ptr_size).with_path_aware_fallback();
            resolver.load_known_values(ctx, method_token);

            // Simulate the relevant state updates in order.
            // If any prior update can't be resolved, the state machine is
            // desynchronized — skip this call site for now (retriable).
            let simulation_ok = Self::simulate_state_updates(
                &mut state,
                &relevant_updates,
                &state_updates,
                &mut resolver,
            );

            if !simulation_ok {
                failures.push((
                    call_site.decryptor,
                    location,
                    FailureReason::NonConstantArgs,
                ));
                continue;
            }

            // Simulate the feeding update call itself
            let feeding_update = &state_updates[call_site.feeding_update_idx];

            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let flag = resolver
                .resolve(feeding_update.flag_var)
                .and_then(|v| v.as_i64())
                .map(|x| x as u8);

            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let increment = resolver
                .resolve(feeding_update.increment_var)
                .and_then(|v| v.as_i64())
                .map(|x| x as u32);

            let (Some(flag), Some(increment)) = (flag, increment) else {
                failures.push((
                    call_site.decryptor,
                    location,
                    FailureReason::NonConstantArgs,
                ));
                continue;
            };

            let state_value = state.next_u32(flag, increment);

            // Get the encoded constant
            let encoded = resolver
                .resolve(call_site.encoded_var)
                .and_then(|v| v.as_i32());

            let Some(encoded) = encoded else {
                failures.push((
                    call_site.decryptor,
                    location,
                    FailureReason::NonConstantArgs,
                ));
                continue;
            };

            // Compute actual key using the provider
            let actual_key = provider.compute_key(u64::from(state_value), encoded);

            // Decrypt using the computed key
            let args = vec![ConstValue::I32(actual_key)];
            let (result, failure) =
                self.try_decrypt_at_call(call_site.decryptor, call_site.call_target, &args);
            if let Some(value) = result {
                self.decryptors.record_success(
                    call_site.decryptor,
                    method_token,
                    location,
                    value.clone(),
                );

                let event_kind = if value.is_string_like() {
                    EventKind::StringDecrypted
                } else {
                    EventKind::ConstantDecrypted
                };
                changes
                    .record(event_kind)
                    .at(method_token, location)
                    .message(format!(
                        "decrypted (CFG mode, flag=0x{flag:02X}, inc=0x{increment:08X}): {value}"
                    ));

                ctx.add_known_value(method_token, call_site.dest, value.clone());

                if let Some(block) = ssa.block_mut(call_site.block_idx) {
                    if let Some(instr) = block.instructions_mut().get_mut(call_site.instr_idx) {
                        instr.set_op(SsaOp::Const {
                            dest: call_site.dest,
                            value,
                        });
                    }
                }

                changed = true;
            } else {
                failures.push((
                    call_site.decryptor,
                    location,
                    failure.unwrap_or(FailureReason::InvalidReturnValue),
                ));
            }
        }

        // Record failures
        for (decryptor, location, reason) in &failures {
            self.decryptors
                .record_failure(*decryptor, method_token, *location, reason.clone());

            log::warn!(
                "CFG mode decryption failed for decryptor 0x{:08X} in method {}: {reason}",
                decryptor.value(),
                method_token
            );
        }

        // Only clean up state machine instructions when ALL call sites have been
        // resolved (successfully decrypted or permanently failed). If retriable
        // failures remain, preserve the state update calls so the next fixpoint
        // iteration can retry with more constants resolved.
        let all_resolved = call_sites.iter().all(|cs| {
            let loc = cs.location();
            self.decryptors.is_already_decrypted(method_token, loc)
                || self.decryptors.has_permanent_failure(method_token, loc)
        });

        if all_resolved {
            // Replace state update calls with Const operations.
            // IMPORTANT: Only clean up the state updates that directly feed
            // decryptor call sites (those whose results are consumed by
            // the XOR+call pattern). Non-feeding updates ("padding") may
            // have their results used as stack values (e.g. popped by the
            // original IL), but replacing them with Const changes the
            // stack-observable behavior when the dest variable is live.
            let feeding_indices: HashSet<usize> =
                call_sites.iter().map(|cs| cs.feeding_update_idx).collect();
            let feeding_updates: Vec<StateUpdateCall> = state_updates
                .iter()
                .enumerate()
                .filter(|(i, _)| feeding_indices.contains(i))
                .map(|(_, u)| u.clone())
                .collect();

            Self::cleanup_state_updates(
                ssa,
                &feeding_updates,
                method_token,
                &changes,
                &mut changed,
            );

            // Remove state machine initialization calls (constructor)
            Self::cleanup_state_initialization(
                ssa,
                &all_seeds,
                method_token,
                &changes,
                &mut changed,
            );
        }

        (changed, changes)
    }

    /// Builds CFG analysis info for a method.
    fn build_cfg_info(ssa: &SsaFunction) -> CfgInfoOwned {
        let cfg = SsaCfg::from_ssa(ssa);
        let node_count = cfg.node_count();
        let entry = cfg.entry();
        let dom_tree = compute_dominators(&cfg, entry);

        let predecessors: Vec<Vec<usize>> = (0..node_count)
            .map(|i| cfg.block_predecessors(i).to_vec())
            .collect();

        CfgInfoOwned {
            dom_tree,
            predecessors,
            node_count,
            entry,
        }
    }

    /// Simulates state updates in order, advancing the state machine.
    ///
    /// Returns `true` if all updates were successfully resolved and applied.
    /// Returns `false` if any update's flag or increment could not be resolved,
    /// which means the state machine is desynchronized and all subsequent
    /// values would be wrong.
    fn simulate_state_updates(
        state: &mut StateMachineState,
        relevant_updates: &[usize],
        all_updates: &[StateUpdateCall],
        resolver: &mut ValueResolver<'_>,
    ) -> bool {
        for &idx in relevant_updates {
            let update = &all_updates[idx];

            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let flag = resolver
                .resolve(update.flag_var)
                .and_then(|v| v.as_i64())
                .map(|x| x as u8);

            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let inc = resolver
                .resolve(update.increment_var)
                .and_then(|v| v.as_i64())
                .map(|x| x as u32);

            if let (Some(flag), Some(inc)) = (flag, inc) {
                let _ = state.next_u32(flag, inc);
            } else {
                return false;
            }
        }
        true
    }

    /// Replaces state update calls with Const operations.
    ///
    /// This is needed because Call ops aren't "pure" so DCE won't remove them.
    fn cleanup_state_updates(
        ssa: &mut SsaFunction,
        state_updates: &[StateUpdateCall],
        method_token: Token,
        changes: &EventLog,
        changed: &mut bool,
    ) {
        for update in state_updates {
            if let Some(block) = ssa.block_mut(update.block_idx) {
                if let Some(instr) = block.instructions_mut().get_mut(update.instr_idx) {
                    instr.set_op(SsaOp::Const {
                        dest: update.dest,
                        value: ConstValue::I32(0),
                    });
                    *changed = true;
                    changes
                        .record(EventKind::InstructionRemoved)
                        .at(method_token, update.block_idx * 1000 + update.instr_idx)
                        .message(format!(
                            "replaced state machine update call with const (result {:?})",
                            update.dest
                        ));
                }
            }
        }
    }

    /// Removes state machine initialization calls (constructor).
    ///
    /// After decryption, the CFGCtx constructor calls are dead code but DCE
    /// won't remove them since Call ops aren't pure. Replace them with Nop.
    fn cleanup_state_initialization(
        ssa: &mut SsaFunction,
        seeds: &[(usize, usize, u32)],
        method_token: Token,
        changes: &EventLog,
        changed: &mut bool,
    ) {
        for &(block_idx, instr_idx, _seed) in seeds {
            if let Some(block) = ssa.block_mut(block_idx) {
                if let Some(instr) = block.instructions_mut().get_mut(instr_idx) {
                    // Constructor calls return void, so replace with Nop
                    instr.set_op(SsaOp::Nop);
                    *changed = true;
                    changes
                        .record(EventKind::InstructionRemoved)
                        .at(method_token, block_idx * 1000 + instr_idx)
                        .message("removed state machine initialization call");
                }
            }
        }
    }
}

impl SsaPass for DecryptionPass {
    fn name(&self) -> &'static str {
        "decryption"
    }

    fn description(&self) -> &'static str {
        "Decrypts obfuscated values by emulating registered decryptor methods"
    }

    fn modification_scope(&self) -> ModificationScope {
        ModificationScope::InstructionsOnly
    }

    fn provides(&self) -> &[PassCapability] {
        &[PassCapability::DecryptedStrings]
    }

    fn initialize(&mut self, _ctx: &CompilerContext) -> Result<()> {
        // This pass relies on DecryptorContext being populated by obfuscator
        // detection before it runs. No additional setup needed.
        Ok(())
    }

    fn finalize(&mut self, _ctx: &CompilerContext) -> Result<()> {
        // Pool lifecycle is managed by the engine — nothing to release here.
        Ok(())
    }

    fn run_on_method(
        &self,
        ssa: &mut SsaFunction,
        method_token: Token,
        ctx: &CompilerContext,
        assembly: &CilObject,
    ) -> Result<bool> {
        // Early exit if no decryptors are registered
        if !self.decryptors.has_decryptors() {
            return Ok(false);
        }

        let ptr_size = PointerSize::from_pe(assembly.file().pe().is_64bit);

        // Track whether any mode made changes
        let mut any_changed = false;

        // Check if this method uses a state machine (CFG mode) - requires sequential processing
        if let Some(provider) = self.get_statemachine_provider_for_method(method_token) {
            let (sm_changed, sm_changes) = self.process_state_machine_mode(
                ssa,
                method_token,
                ctx,
                assembly,
                &*provider,
                ptr_size,
            );
            if sm_changed {
                any_changed = true;
            }
            if !sm_changes.is_empty() {
                ctx.events.merge(&sm_changes);
            }
            // Fall through to normal-mode processing to catch any remaining
            // decryptor calls not matched by the CFG XOR pattern. In CFG-mode
            // methods, some calls may have pre-folded arguments that appear as
            // direct constants (the XOR was computed at IL generation time).
            // Normal-mode processing handles these correctly since the constant
            // IS the correct key.
        }

        let changes = EventLog::new();

        let mut resolver = ValueResolver::new(&*ssa, ptr_size).with_path_aware_fallback();
        resolver.load_known_values(ctx, method_token);

        // Phase 1: Collect decryption candidates (sequential)
        type DecryptionCandidate = (usize, usize, SsaVarId, Token, Token, usize, Vec<ConstValue>);
        let mut candidates: Vec<DecryptionCandidate> = Vec::new();
        let mut failures: Vec<(Token, usize, FailureReason)> = Vec::new();

        for (block_idx, block) in ssa.iter_blocks() {
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                let (call_target, args, dest) = match instr.op() {
                    SsaOp::Call { method, args, dest } | SsaOp::CallVirt { method, args, dest } => {
                        (method.token(), args, *dest)
                    }
                    _ => continue,
                };

                let Some(dest) = dest else { continue };
                let Some(decryptor) = self.decryptors.resolve_decryptor(call_target) else {
                    continue;
                };

                let location = block_idx * 1000 + instr_idx;

                if self.decryptors.is_already_decrypted(method_token, location) {
                    continue;
                }
                if self
                    .decryptors
                    .has_permanent_failure(method_token, location)
                {
                    continue;
                }

                let Some(arg_constants) = Self::get_arg_constants(args, &mut resolver) else {
                    failures.push((decryptor, location, FailureReason::NonConstantArgs));
                    continue;
                };

                candidates.push((
                    block_idx,
                    instr_idx,
                    dest,
                    decryptor,
                    call_target,
                    location,
                    arg_constants,
                ));
            }
        }

        // Phase 2: Run decryptions in parallel (O(1) CoW fork per emulation)
        // Collect results as Option - Some for success, None signals failure stored in parallel vec
        let parallel_failures = Mutex::new(Vec::new());

        let successes: Vec<_> = candidates
            .into_par_iter()
            .filter_map(
                |(block_idx, instr_idx, dest, decryptor, call_target, location, args)| {
                    let (result, failure) = self.try_decrypt_at_call(decryptor, call_target, &args);

                    if let Some(value) = result {
                        Some((block_idx, instr_idx, dest, decryptor, location, value))
                    } else {
                        if let Ok(mut guard) = parallel_failures.lock() {
                            guard.push((
                                decryptor,
                                location,
                                failure.unwrap_or(FailureReason::InvalidReturnValue),
                            ));
                        }
                        None
                    }
                },
            )
            .collect();

        // Merge parallel failures into main failures vec
        failures.extend(
            parallel_failures
                .into_inner()
                .map_err(|e| Error::LockError(format!("parallel failures lock: {e}")))?,
        );

        // Phase 3: Apply results (sequential - SSA mutation not thread-safe)
        for (block_idx, instr_idx, dest, decryptor, location, value) in successes {
            self.decryptors
                .record_success(decryptor, method_token, location, value.clone());

            let event_kind = if value.is_string_like() {
                EventKind::StringDecrypted
            } else {
                EventKind::ConstantDecrypted
            };
            changes
                .record(event_kind)
                .at(method_token, block_idx * 1000 + instr_idx)
                .message(format!("decrypted: {value}"));

            ctx.add_known_value(method_token, dest, value.clone());

            if let Some(block) = ssa.block_mut(block_idx) {
                if let Some(instr) = block.instructions_mut().get_mut(instr_idx) {
                    instr.set_op(SsaOp::Const { dest, value });
                }
            }
        }

        // Record failures
        for (decryptor, location, reason) in &failures {
            self.decryptors
                .record_failure(*decryptor, method_token, *location, reason.clone());

            log::warn!(
                "Decryption failed for decryptor 0x{:08X} in method {}: {reason}",
                decryptor.value(),
                method_token
            );
        }

        // Determine if actual transformations were made
        let normal_changed = changes.iter().any(|e| e.kind.is_transformation());
        if !changes.is_empty() {
            ctx.events.merge(&changes);
        }
        Ok(any_changed || normal_changed)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{
        analysis::{
            CallGraph, ConstValue, MethodRef, SsaFunction, SsaFunctionBuilder, SsaType, SsaVarId,
            ValueResolver,
        },
        compiler::SsaPass,
        deobfuscation::{
            context::AnalysisContext, passes::DecryptionPass, DeobfuscationEngine, EngineConfig,
        },
        metadata::{token::Token, typesystem::PointerSize},
        test::helpers::test_assembly_arc,
    };

    /// Helper to create a minimal analysis context for testing.
    fn create_test_context() -> AnalysisContext {
        let call_graph = Arc::new(CallGraph::new());
        AnalysisContext::new(call_graph)
    }

    #[test]
    fn test_pass_creation() {
        let ctx = create_test_context();
        let pass = DecryptionPass::new(&ctx);
        assert_eq!(pass.name(), "decryption");
        assert!(!pass.description().is_empty());
    }

    #[test]
    fn test_run_no_decryptors() {
        let ctx = create_test_context();
        let pass = DecryptionPass::new(&ctx);

        let method_token = Token::new(0x06000001);
        let mut ssa = SsaFunctionBuilder::new(0, 0)
            .build_with(|f| {
                f.block(0, |b| {
                    let _ = b.const_i32(42);
                    b.ret();
                });
            })
            .unwrap();

        // No decryptors registered, should return false (no changes)
        let changed = pass
            .run_on_method(&mut ssa, method_token, &ctx, &test_assembly_arc())
            .unwrap();
        assert!(!changed);
    }

    #[test]
    fn test_run_with_decryptor_no_calls() {
        let ctx = create_test_context();

        // Register a decryptor
        let decryptor_token = Token::new(0x06000002);
        ctx.decryptors.register(decryptor_token);

        let pass = DecryptionPass::new(&ctx);

        let method_token = Token::new(0x06000001);
        let mut ssa = SsaFunctionBuilder::new(0, 0)
            .build_with(|f| {
                f.block(0, |b| {
                    let _ = b.const_i32(42);
                    b.ret();
                });
            })
            .unwrap();

        // Has decryptors but no calls to them
        let changed = pass
            .run_on_method(&mut ssa, method_token, &ctx, &test_assembly_arc())
            .unwrap();
        assert!(!changed);
    }

    #[test]
    fn test_run_call_to_decryptor_no_dest() {
        let ctx = create_test_context();

        // Register a decryptor
        let decryptor_token = Token::new(0x06000002);
        ctx.decryptors.register(decryptor_token);

        let pass = DecryptionPass::new(&ctx);

        let method_token = Token::new(0x06000001);
        let mut ssa = SsaFunctionBuilder::new(0, 0)
            .build_with(|f| {
                f.block(0, |b| {
                    // Call with no destination
                    b.call_void(MethodRef::new(decryptor_token), &[]);
                    b.ret();
                });
            })
            .unwrap();

        // Call without destination, can't replace
        let changed = pass
            .run_on_method(&mut ssa, method_token, &ctx, &test_assembly_arc())
            .unwrap();
        assert!(!changed);
    }

    #[test]
    fn test_run_call_to_decryptor_non_constant_args() {
        let ctx = create_test_context();

        // Register a decryptor
        let decryptor_token = Token::new(0x06000002);
        ctx.decryptors.register(decryptor_token);

        let pass = DecryptionPass::new(&ctx);

        let method_token = Token::new(0x06000001);
        let mut ssa = SsaFunctionBuilder::new(1, 0)
            .build_with(|f| {
                let arg0 = f.arg(0, SsaType::I32);
                f.block(0, |b| {
                    // Call with non-constant argument
                    let _ = b.call(MethodRef::new(decryptor_token), &[arg0], SsaType::I32);
                    b.ret();
                });
            })
            .unwrap();

        // Argument is not in known_values, should fail
        let changed = pass
            .run_on_method(&mut ssa, method_token, &ctx, &test_assembly_arc())
            .unwrap();
        assert!(!changed);

        // Should have recorded a failure
        assert_eq!(ctx.decryptors.total_failed(), 1);
    }

    #[test]
    fn test_run_call_to_non_decryptor() {
        let ctx = create_test_context();

        // Register a decryptor
        let decryptor_token = Token::new(0x06000002);
        ctx.decryptors.register(decryptor_token);

        let pass = DecryptionPass::new(&ctx);

        let method_token = Token::new(0x06000001);
        let other_method = Token::new(0x06000003);
        let mut ssa = SsaFunctionBuilder::new(0, 0)
            .build_with(|f| {
                f.block(0, |b| {
                    // Call to a different method (not a decryptor)
                    let _ = b.call(MethodRef::new(other_method), &[], SsaType::I32);
                    b.ret();
                });
            })
            .unwrap();

        let changed = pass
            .run_on_method(&mut ssa, method_token, &ctx, &test_assembly_arc())
            .unwrap();
        assert!(!changed);
    }

    #[test]
    fn test_methodspec_resolution() {
        let ctx = create_test_context();

        // Register a decryptor and map a MethodSpec to it
        let decryptor_token = Token::new(0x06000002);
        let methodspec_token = Token::new(0x2b000001);
        ctx.decryptors.register(decryptor_token);
        ctx.decryptors
            .map_methodspec(methodspec_token, decryptor_token);

        let pass = DecryptionPass::new(&ctx);

        let method_token = Token::new(0x06000001);
        let mut ssa = SsaFunctionBuilder::new(0, 0)
            .build_with(|f| {
                f.block(0, |b| {
                    let c = b.const_i32(42);
                    // Call via MethodSpec with a destination so we can attempt decryption
                    let _ = b.call(MethodRef::new(methodspec_token), &[c], SsaType::I32);
                    b.ret();
                });
            })
            .unwrap();

        // Set up the constant arg
        let var_id = ssa.block(0).unwrap().instructions()[0].op().dest().unwrap();
        ctx.add_known_value(method_token, var_id, ConstValue::I32(42));

        // This will try to decrypt but fail (no assembly for emulation)
        // The point is that it recognized the MethodSpec as a decryptor call
        let _ = pass.run_on_method(&mut ssa, method_token, &ctx, &test_assembly_arc());

        // Verify the MethodSpec was resolved to the decryptor and a failure was recorded
        // (failure because there's no assembly to emulate against)
        assert_eq!(
            ctx.decryptors.total_failed(),
            1,
            "Should record failure for MethodSpec call (recognized but emulation failed)"
        );
    }

    #[test]
    fn test_pass_initialize() {
        let ctx = create_test_context();
        let mut pass = DecryptionPass::new(&ctx);

        let result = pass.initialize(&ctx);
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_arg_constants_all_known() {
        let ctx = create_test_context();
        let ssa = SsaFunction::new(0, 0);

        let method = Token::new(0x06000001);
        let var1 = SsaVarId::from_index(0);
        let var2 = SsaVarId::from_index(1);

        ctx.add_known_value(method, var1, ConstValue::I32(42));
        ctx.add_known_value(method, var2, ConstValue::I32(100));

        let mut resolver = ValueResolver::new(&ssa, PointerSize::Bit64);
        resolver.load_known_values(&ctx, method);
        let args = vec![var1, var2];
        let result = DecryptionPass::get_arg_constants(&args, &mut resolver);

        assert!(result.is_some());
        let constants = result.unwrap();
        assert_eq!(constants.len(), 2);
        assert_eq!(constants[0], ConstValue::I32(42));
        assert_eq!(constants[1], ConstValue::I32(100));
    }

    #[test]
    fn test_get_arg_constants_partial() {
        let ctx = create_test_context();
        let ssa = SsaFunction::new(0, 0);

        let method = Token::new(0x06000001);
        let var1 = SsaVarId::from_index(0);
        let var2 = SsaVarId::from_index(1);

        ctx.add_known_value(method, var1, ConstValue::I32(42));
        // var2 not set

        let mut resolver = ValueResolver::new(&ssa, PointerSize::Bit64);
        resolver.load_known_values(&ctx, method);
        let args = vec![var1, var2];
        let result = DecryptionPass::get_arg_constants(&args, &mut resolver);

        // Should return None because not all args are known
        assert!(result.is_none());
    }

    #[test]
    fn test_get_arg_constants_empty() {
        let ctx = create_test_context();
        let ssa = SsaFunction::new(0, 0);
        let method = Token::new(0x06000001);

        let mut resolver = ValueResolver::new(&ssa, PointerSize::Bit64);
        resolver.load_known_values(&ctx, method);
        let args: Vec<SsaVarId> = vec![];
        let result = DecryptionPass::get_arg_constants(&args, &mut resolver);
        assert!(result.is_some());
        assert!(result.unwrap().is_empty());
    }

    /// Integration test: Verifies constants decryption on a real ConfuserEx sample.
    ///
    /// This test runs the full deobfuscation pipeline on `mkaring_constants.exe`
    /// which has ConfuserEx constants protection enabled.
    #[test]
    fn test_constants_decryption_integration() {
        const CONSTANTS_PATH: &str = "tests/samples/packers/confuserex/1.6.0/mkaring_constants.exe";

        // Run full deobfuscation pipeline (ConfuserEx is auto-registered)
        let engine = DeobfuscationEngine::new(EngineConfig::default());
        let result = engine.process_file(CONSTANTS_PATH);

        match result {
            Ok((_deobfuscated, result)) => {
                // Verify that constants were actually decrypted.
                // The mkaring_constants.exe sample has ConfuserEx constants protection.
                let stats = result.stats();

                // Assert meaningful decryption occurred
                assert!(
                    stats.constants_folded > 30,
                    "Expected at least 30 constants decrypted/folded, got {}",
                    stats.constants_folded
                );

                assert!(
                    stats.methods_transformed > 0,
                    "Expected some methods to be transformed"
                );

                assert!(
                    stats.methods_regenerated > 0,
                    "Expected some methods to have code regenerated"
                );
            }
            Err(e) => {
                panic!("Deobfuscation should succeed: {:?}", e);
            }
        }
    }
}
