//! Small method inlining and proxy devirtualization pass.
//!
//! This pass inlines small, pure methods at their call sites and devirtualizes
//! proxy methods to expose further optimization opportunities. It's particularly
//! effective for:
//!
//! - Proxy methods that just forward to another method (even impure ones)
//! - Simple getters/setters
//! - Constant-returning methods
//! - String decryptor helpers
//!
//! # Inlining Criteria
//!
//! A method is considered for inlining if:
//! 1. It's small enough (instruction count <= threshold)
//! 2. It's pure or read-only (no global side effects)
//! 3. It doesn't recurse (directly or indirectly)
//! 4. The call is non-virtual (single target)
//! 5. The callee SSA is available in the context
//!
//! # Proxy Devirtualization
//!
//! Additionally, proxy methods are detected and devirtualized regardless of purity.
//! A proxy method is one that:
//! 1. Contains a single call instruction (the forwarded call)
//! 2. Forwards parameters directly as arguments (possibly reordered)
//! 3. Returns the call result (if non-void)
//! 4. Has no other side effects besides the forwarded call
//!
//! When a proxy is detected, the call is replaced with a direct call to the
//! forwarding target, eliminating the proxy overhead.
//!
//! # Safety
//!
//! Inlining preserves semantics by:
//! - Only inlining pure/read-only methods
//! - Properly remapping all variable IDs
//! - Handling parameter binding correctly
//! - Replacing return with assignment to destination
//!
//! Proxy devirtualization preserves semantics because the forwarded call
//! happens exactly once in either case - we're just eliminating the wrapper.

use std::{collections::HashMap, sync::Arc};

use crate::{
    analysis::{
        ConstValue, DefSite, MethodRef, ReturnInfo, SsaFunction, SsaInstruction, SsaOp, SsaVarId,
        SsaVariable, VariableOrigin,
    },
    compiler::{pass::SsaPass, CompilerContext, EventKind, EventLog},
    metadata::{tables::MemberRefSignature, token::Token, typesystem::CilTypeReference},
    CilObject, Result,
};

/// Type of inlining to perform at a call site.
#[derive(Debug, Clone)]
enum InlineAction {
    /// Full inlining: copy callee's body into caller
    FullInline,
    /// Proxy devirtualization: replace call target with forwarding target
    ProxyDevirtualize {
        target_method: MethodRef,
        arg_mapping: Vec<usize>,
        is_virtual: bool,
    },
    /// No-op elimination: remove the call entirely (void method that just returns)
    NoOpEliminate,
    /// Constant fold: replace the call with a constant value
    ConstantFold(ConstValue),
}

/// A candidate call site for inlining or devirtualization.
#[derive(Debug, Clone)]
struct InlineCandidate {
    /// Block index containing the call
    block_idx: usize,
    /// Instruction index within the block
    instr_idx: usize,
    /// Token of the method being called (the callee/proxy)
    callee_token: Token,
    /// What action to take at this call site
    action: InlineAction,
}

/// Method-specific context for inlining operations.
///
/// This struct holds all the common parameters needed during inlining of a single
/// method, reducing parameter passing overhead and making the code cleaner.
struct InliningContext<'a> {
    /// Reference to the pass configuration (for thresholds, etc.)
    pass: &'a InliningPass,
    /// The caller's SSA being modified
    caller_ssa: &'a mut SsaFunction,
    /// Token of the method being processed
    caller_token: Token,
    /// The analysis context with method summaries, call graph, etc.
    analysis_ctx: &'a CompilerContext,
    /// The assembly for resolving tokens
    assembly: &'a Arc<CilObject>,
    /// Event log for recording changes
    changes: EventLog,
}

impl<'a> InliningContext<'a> {
    /// Creates a new inlining context for processing a method.
    ///
    /// The context holds all the state needed for inlining operations on a single
    /// method, reducing parameter passing overhead in helper methods.
    ///
    /// # Arguments
    ///
    /// * `pass` - Reference to the inlining pass configuration.
    /// * `caller_ssa` - Mutable reference to the caller's SSA being modified.
    /// * `caller_token` - Token identifying the method being processed.
    /// * `analysis_ctx` - Analysis context with method summaries and call graph.
    /// * `assembly` - Assembly for resolving tokens.
    fn new(
        pass: &'a InliningPass,
        caller_ssa: &'a mut SsaFunction,
        caller_token: Token,
        analysis_ctx: &'a CompilerContext,
        assembly: &'a Arc<CilObject>,
    ) -> Self {
        Self {
            pass,
            caller_ssa,
            caller_token,
            analysis_ctx,
            assembly,
            changes: EventLog::new(),
        }
    }

    /// Returns whether any changes were made during inlining.
    ///
    /// # Returns
    ///
    /// `true` if at least one inlining operation was performed.
    fn has_changes(&self) -> bool {
        !self.changes.is_empty()
    }

    /// Consumes the context and returns the accumulated event log.
    ///
    /// # Returns
    ///
    /// The event log containing all recorded changes from inlining operations.
    fn into_changes(self) -> EventLog {
        self.changes
    }

    /// Checks if a callee is a valid target for inlining or devirtualization.
    ///
    /// A method is invalid for inlining if it:
    /// - Is the same as the caller (self-recursion)
    /// - Is a registered decryptor (handled by decryption passes)
    /// - Is a registered dispatcher (control flow dispatcher)
    ///
    /// # Arguments
    ///
    /// * `callee_token` - Token of the method being considered for inlining.
    ///
    /// # Returns
    ///
    /// `true` if the callee can potentially be inlined.
    fn is_valid_target(&self, callee_token: Token) -> bool {
        // Don't inline self-recursion
        if callee_token == self.caller_token {
            return false;
        }

        // Check if this method should not be inlined (decryptors, dispatchers, etc.)
        if self.analysis_ctx.no_inline.contains(&callee_token) {
            return false;
        }

        true
    }

    /// Checks if a method should be fully inlined at a call site.
    ///
    /// A method qualifies for full inlining if it:
    /// - Is a valid target (not self-recursion, decryptor, or dispatcher)
    /// - Is smaller than the inlining threshold
    /// - Is pure or read-only (no global side effects)
    /// - Does not contain recursive calls
    ///
    /// # Arguments
    ///
    /// * `callee_token` - Token of the method being considered for inlining.
    ///
    /// # Returns
    ///
    /// `true` if the method should be inlined.
    fn should_inline(&self, callee_token: Token) -> bool {
        if !self.is_valid_target(callee_token) {
            return false;
        }

        // Check if we have the callee's SSA and evaluate criteria
        self.analysis_ctx
            .with_ssa(callee_token, |callee_ssa| {
                // Check size threshold
                let instr_count = callee_ssa.instruction_count();
                if instr_count > self.pass.inline_threshold {
                    return false;
                }

                // Check purity - only inline pure or read-only methods
                if !callee_ssa.purity().can_inline() {
                    return false;
                }

                // Check for recursive calls in the callee
                if self.has_recursive_call(callee_token, callee_ssa) {
                    return false;
                }

                true
            })
            .unwrap_or(false)
    }

    /// Checks if a method has any recursive calls (direct or indirect).
    ///
    /// This checks for both direct self-calls and indirect recursion through
    /// the call graph (e.g., A calls B which calls A).
    ///
    /// # Arguments
    ///
    /// * `method_token` - Token of the method to check for recursion.
    /// * `ssa` - The SSA representation of the method.
    ///
    /// # Returns
    ///
    /// `true` if the method contains any recursive calls.
    fn has_recursive_call(&self, method_token: Token, ssa: &SsaFunction) -> bool {
        for block in ssa.blocks() {
            for instr in block.instructions() {
                if let SsaOp::Call { method, .. } | SsaOp::CallVirt { method, .. } = instr.op() {
                    if method.token() == method_token {
                        return true;
                    }
                    // Check for indirect recursion via call graph
                    let callees = self.analysis_ctx.call_graph.callees(method.token());
                    if callees.contains(&method_token) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Checks if a method should be devirtualized as a proxy.
    ///
    /// Unlike full inlining, proxy devirtualization doesn't require purity
    /// because we're just changing the call target, not duplicating code.
    /// This is effective for wrapper methods that just forward calls.
    ///
    /// # Arguments
    ///
    /// * `callee_token` - Token of the method being considered for devirtualization.
    ///
    /// # Returns
    ///
    /// If the method is a proxy, returns `Some((target_method, arg_mapping, is_virtual))`:
    /// - `target_method` - The forwarding target method.
    /// - `arg_mapping` - Maps proxy parameter indices to target argument positions.
    /// - `is_virtual` - Whether the forwarded call is virtual.
    ///
    /// Returns `None` if the method is not a proxy.
    fn should_devirtualize_proxy(
        &self,
        callee_token: Token,
    ) -> Option<(MethodRef, Vec<usize>, bool)> {
        if !self.is_valid_target(callee_token) {
            return None;
        }

        // Check for proxy pattern
        self.analysis_ctx
            .with_ssa(callee_token, |callee_ssa| {
                InliningPass::detect_proxy_pattern(callee_ssa)
            })
            .flatten()
    }

    /// Checks if a method is a no-op that can be eliminated at call sites.
    ///
    /// A no-op method is one that:
    /// - Just returns (void method with only `ret`)
    /// - Always returns a constant value
    /// - Has no side effects (is pure)
    ///
    /// # Arguments
    ///
    /// * `callee_token` - Token of the method being considered.
    ///
    /// # Returns
    ///
    /// - `Some(None)` - Void no-op: call can be replaced with Nop.
    /// - `Some(Some(ConstValue))` - Constant return: call can be replaced with constant.
    /// - `None` - Not a no-op method.
    fn detect_noop_method(&self, callee_token: Token) -> Option<Option<ConstValue>> {
        if !self.is_valid_target(callee_token) {
            return None;
        }

        // Check if callee is a no-op using SSA analysis
        self.analysis_ctx
            .with_ssa(callee_token, |callee_ssa| {
                // Must have no side effects to safely eliminate
                if !callee_ssa.purity().can_eliminate_if_unused() {
                    return None;
                }

                // Check what the method returns
                match callee_ssa.return_info() {
                    ReturnInfo::Void => Some(None),
                    ReturnInfo::Constant(val) => Some(Some(val.clone())),
                    _ => None,
                }
            })
            .flatten()
    }

    /// Resolves a token to its MethodDef equivalent.
    ///
    /// This is necessary because:
    /// - SSA forms are stored under MethodDef tokens
    /// - Call instructions may use MemberRef tokens even for internal methods
    /// - We need to match MemberRef -> MethodDef to look up the callee's SSA
    ///
    /// # Arguments
    ///
    /// * `token` - The token to resolve (may be MethodDef, MemberRef, or MethodSpec).
    ///
    /// # Returns
    ///
    /// The resolved MethodDef token, or the original token if resolution fails.
    fn resolve_to_method_def(&self, token: Token) -> Token {
        let table_id = token.table();

        // Already a MethodDef - return as-is
        if table_id == 0x06 {
            return token;
        }

        // MemberRef - try to resolve to MethodDef
        if table_id == 0x0A {
            let refs = self.assembly.refs_members();
            if let Some(member_ref_entry) = refs.get(&token) {
                let member_ref = member_ref_entry.value();

                // Only handle method signatures, not fields
                let MemberRefSignature::Method(ref _method_sig) = member_ref.signature else {
                    return token;
                };

                // Check if declared by a TypeDef (internal type)
                if let CilTypeReference::TypeDef(type_ref) = &member_ref.declaredby {
                    if let Some(type_info) = type_ref.upgrade() {
                        if let Some(method) = type_info
                            .query_methods()
                            .name(&member_ref.name)
                            .find_first()
                        {
                            return method.token;
                        }
                    }
                }
            }
        }

        token
    }

    /// Finds all inlinable and devirtualizable call sites in the method.
    ///
    /// Scans the caller's SSA for call instructions and evaluates each one
    /// against the inlining criteria. Candidates are prioritized as:
    /// 1. Full inlining (for small, pure methods)
    /// 2. No-op elimination (for void/constant-returning pure methods)
    /// 3. Proxy devirtualization (for call forwarding wrappers)
    ///
    /// # Returns
    ///
    /// A vector of candidates that can be inlined or devirtualized.
    fn find_candidates(&self) -> Vec<InlineCandidate> {
        let mut candidates = Vec::new();

        for (block_idx, instr_idx, instr) in self.caller_ssa.iter_instructions() {
            let raw_callee_token = match instr.op() {
                SsaOp::Call { method, .. } => method.token(),
                SsaOp::CallVirt { method, .. } => {
                    let token = method.token();
                    // Check if this is actually polymorphic
                    if self
                        .analysis_ctx
                        .call_graph
                        .resolver()
                        .is_polymorphic(token)
                    {
                        continue;
                    }
                    token
                }
                _ => continue,
            };

            // Resolve MemberRef tokens to MethodDef tokens for SSA lookup
            let callee_token = self.resolve_to_method_def(raw_callee_token);

            // Try full inlining first (for pure methods)
            if self.should_inline(callee_token) {
                candidates.push(InlineCandidate {
                    block_idx,
                    instr_idx,
                    callee_token,
                    action: InlineAction::FullInline,
                });
            }
            // Try no-op elimination
            else if let Some(noop_result) = self.detect_noop_method(callee_token) {
                let action = match noop_result {
                    None => InlineAction::NoOpEliminate,
                    Some(val) => InlineAction::ConstantFold(val),
                };
                candidates.push(InlineCandidate {
                    block_idx,
                    instr_idx,
                    callee_token,
                    action,
                });
            }
            // Try proxy devirtualization
            else if let Some((target_method, arg_mapping, is_virtual)) =
                self.should_devirtualize_proxy(callee_token)
            {
                candidates.push(InlineCandidate {
                    block_idx,
                    instr_idx,
                    callee_token,
                    action: InlineAction::ProxyDevirtualize {
                        target_method,
                        arg_mapping,
                        is_virtual,
                    },
                });
            }
        }

        candidates
    }

    /// Processes a single inlining candidate.
    ///
    /// Dispatches to the appropriate inlining strategy based on the candidate's
    /// action type. Also marks successfully inlined methods in the analysis context.
    ///
    /// # Arguments
    ///
    /// * `candidate` - The inlining candidate to process.
    ///
    /// # Returns
    ///
    /// `true` if the inlining operation was successful.
    fn process_candidate(&mut self, candidate: &InlineCandidate) -> bool {
        let call_op = match self.caller_ssa.block(candidate.block_idx) {
            Some(block) => match block.instructions().get(candidate.instr_idx) {
                Some(instr) => instr.op().clone(),
                None => return false,
            },
            None => return false,
        };

        let success = match &candidate.action {
            InlineAction::FullInline => {
                // Get the callee SSA
                let Some(callee_ssa) = self
                    .analysis_ctx
                    .with_ssa(candidate.callee_token, |ssa| ssa.clone())
                else {
                    return false;
                };

                self.inline_call(
                    &callee_ssa,
                    candidate.block_idx,
                    candidate.instr_idx,
                    &call_op,
                    candidate.callee_token,
                )
            }
            InlineAction::ProxyDevirtualize {
                target_method,
                arg_mapping,
                is_virtual,
            } => self.devirtualize_proxy(
                candidate.block_idx,
                candidate.instr_idx,
                &call_op,
                target_method,
                arg_mapping,
                *is_virtual,
                candidate.callee_token,
            ),
            InlineAction::NoOpEliminate => self.eliminate_noop_call(
                candidate.block_idx,
                candidate.instr_idx,
                &call_op,
                candidate.callee_token,
            ),
            InlineAction::ConstantFold(const_val) => self.fold_constant_call(
                candidate.block_idx,
                candidate.instr_idx,
                &call_op,
                const_val,
                candidate.callee_token,
            ),
        };

        if success {
            self.analysis_ctx.mark_inlined(candidate.callee_token);
        }
        success
    }

    /// Inlines a callee method at a specific call site.
    ///
    /// This method handles different return patterns optimally:
    /// - Constant returns: Replace call with constant assignment
    /// - Pass-through returns: Replace call with copy from argument
    /// - Void returns: Replace call with Nop
    /// - Pure computation: Perform full block inlining
    ///
    /// # Arguments
    ///
    /// * `callee_ssa` - The callee's SSA representation.
    /// * `call_block_idx` - Block index of the call instruction in the caller.
    /// * `call_instr_idx` - Instruction index within the block.
    /// * `call_op` - The call operation being inlined.
    /// * `callee_token` - Token of the callee (for logging).
    ///
    /// # Returns
    ///
    /// `true` if inlining was successful.
    fn inline_call(
        &mut self,
        callee_ssa: &SsaFunction,
        call_block_idx: usize,
        call_instr_idx: usize,
        call_op: &SsaOp,
        callee_token: Token,
    ) -> bool {
        // Extract call information
        let (dest, args) = match call_op {
            SsaOp::Call { dest, args, .. } | SsaOp::CallVirt { dest, args, .. } => {
                (*dest, args.clone())
            }
            _ => return false,
        };

        // For very simple cases, we can do a simpler inline
        match callee_ssa.return_info() {
            ReturnInfo::Constant(value) => {
                if let Some(dest_var) = dest {
                    if let Some(block) = self.caller_ssa.block_mut(call_block_idx) {
                        let instr = &mut block.instructions_mut()[call_instr_idx];
                        instr.set_op(SsaOp::Const {
                            dest: dest_var,
                            value: value.clone(),
                        });
                        self.changes
                            .record(EventKind::MethodInlined)
                            .at(self.caller_token, call_instr_idx)
                            .message(format!("inlined constant {:?}", callee_token));
                        return true;
                    }
                } else {
                    // Void destination but constant return - just remove the call
                    if let Some(block) = self.caller_ssa.block_mut(call_block_idx) {
                        let instr = &mut block.instructions_mut()[call_instr_idx];
                        instr.set_op(SsaOp::Nop);
                        self.changes
                            .record(EventKind::MethodInlined)
                            .at(self.caller_token, call_instr_idx)
                            .message(format!("eliminated pure call {:?}", callee_token));
                        return true;
                    }
                }
            }
            ReturnInfo::PassThrough(param_idx) => {
                if let Some(dest_var) = dest {
                    if let Some(&src_var) = args.get(param_idx) {
                        if let Some(block) = self.caller_ssa.block_mut(call_block_idx) {
                            let instr = &mut block.instructions_mut()[call_instr_idx];
                            instr.set_op(SsaOp::Copy {
                                dest: dest_var,
                                src: src_var,
                            });
                            self.changes
                                .record(EventKind::MethodInlined)
                                .at(self.caller_token, call_instr_idx)
                                .message(format!("inlined passthrough {:?}", callee_token));
                            return true;
                        }
                    }
                }
            }
            ReturnInfo::Void => {
                if let Some(block) = self.caller_ssa.block_mut(call_block_idx) {
                    let instr = &mut block.instructions_mut()[call_instr_idx];
                    instr.set_op(SsaOp::Nop);
                    self.changes
                        .record(EventKind::MethodInlined)
                        .at(self.caller_token, call_instr_idx)
                        .message(format!("eliminated void call {:?}", callee_token));
                    return true;
                }
            }
            ReturnInfo::PureComputation | ReturnInfo::Dynamic | ReturnInfo::Unknown => {
                return self.inline_full(
                    callee_ssa,
                    call_block_idx,
                    call_instr_idx,
                    dest,
                    &args,
                    callee_token,
                );
            }
        }

        false
    }

    /// Performs full SSA inlining by copying blocks from callee into caller.
    ///
    /// This handles the complex case where simple replacement isn't possible.
    /// The algorithm:
    /// 1. Map callee parameters to call arguments
    /// 2. Copy callee instructions with remapped variable IDs
    /// 3. Replace the call with inlined instructions
    /// 4. Handle return value assignment if needed
    ///
    /// Currently only supports single-block callees to keep complexity manageable.
    ///
    /// # Arguments
    ///
    /// * `callee_ssa` - The callee's SSA representation.
    /// * `call_block_idx` - Block index of the call instruction.
    /// * `call_instr_idx` - Instruction index within the block.
    /// * `dest` - Optional destination variable for the call result.
    /// * `args` - Arguments passed to the call.
    /// * `callee_token` - Token of the callee (for logging).
    ///
    /// # Returns
    ///
    /// `true` if full inlining was successful.
    fn inline_full(
        &mut self,
        callee_ssa: &SsaFunction,
        call_block_idx: usize,
        call_instr_idx: usize,
        dest: Option<SsaVarId>,
        args: &[SsaVarId],
        callee_token: Token,
    ) -> bool {
        // Only inline single-block callees for now
        if callee_ssa.blocks().len() != 1 {
            return false;
        }

        let Some(callee_block) = callee_ssa.blocks().first() else {
            return false;
        };

        // Build variable remapping
        let mut var_remap: HashMap<SsaVarId, SsaVarId> = HashMap::new();

        // Map callee parameters to call arguments
        for (param_idx, &arg_var) in args.iter().enumerate() {
            if let Some(param_var) = callee_ssa
                .variables_from_argument(param_idx as u16)
                .find(|v| v.version() == 0)
            {
                var_remap.insert(param_var.id(), arg_var);
            }
        }

        // Collect instructions to inline (excluding return)
        let mut inlined_ops: Vec<SsaOp> = Vec::new();
        let mut return_value: Option<SsaVarId> = None;

        for instr in callee_block.instructions() {
            let op = instr.op();
            if let SsaOp::Return { value } = op {
                return_value = *value;
            } else {
                let remapped_op = Self::remap_op(op, &mut var_remap, callee_ssa, self.caller_ssa);
                inlined_ops.push(remapped_op);
            }
        }

        // Modify the caller
        let Some(block) = self.caller_ssa.block_mut(call_block_idx) else {
            return false;
        };

        // Replace call instruction with first inlined op (or Nop if empty)
        if let Some(first_op) = inlined_ops.first().cloned() {
            block.instructions_mut()[call_instr_idx].set_op(first_op);
        } else {
            block.instructions_mut()[call_instr_idx].set_op(SsaOp::Nop);
        }

        // Insert remaining inlined ops
        let instructions = block.instructions_mut();
        for (i, op) in inlined_ops.into_iter().skip(1).enumerate() {
            instructions.insert(call_instr_idx + 1 + i, SsaInstruction::synthetic(op));
        }

        // Handle return value
        if let (Some(dest_var), Some(ret_var)) = (dest, return_value) {
            let remapped_ret = var_remap.get(&ret_var).copied().unwrap_or(ret_var);

            if dest_var != remapped_ret {
                let Some(block) = self.caller_ssa.block_mut(call_block_idx) else {
                    return false;
                };
                let insert_pos = call_instr_idx + 1;
                block.instructions_mut().insert(
                    insert_pos,
                    SsaInstruction::synthetic(SsaOp::Copy {
                        dest: dest_var,
                        src: remapped_ret,
                    }),
                );
            }
        }

        self.changes
            .record(EventKind::MethodInlined)
            .at(self.caller_token, call_instr_idx)
            .message(format!("fully inlined {:?}", callee_token));
        true
    }

    /// Devirtualizes a proxy call by replacing it with a direct call to the target.
    ///
    /// This doesn't inline the proxy body - it just changes the call target and
    /// remaps the arguments according to the proxy's parameter mapping.
    ///
    /// # Arguments
    ///
    /// * `call_block_idx` - Block index of the call instruction.
    /// * `call_instr_idx` - Instruction index within the block.
    /// * `call_op` - The call operation being devirtualized.
    /// * `target_method` - The forwarding target method.
    /// * `arg_mapping` - Maps proxy parameter indices to target argument positions.
    /// * `is_virtual` - Whether the forwarded call should be virtual.
    /// * `proxy_token` - Token of the proxy method (for logging).
    ///
    /// # Returns
    ///
    /// `true` if devirtualization was successful.
    #[allow(clippy::too_many_arguments)]
    fn devirtualize_proxy(
        &mut self,
        call_block_idx: usize,
        call_instr_idx: usize,
        call_op: &SsaOp,
        target_method: &MethodRef,
        arg_mapping: &[usize],
        is_virtual: bool,
        proxy_token: Token,
    ) -> bool {
        let (dest, original_args) = match call_op {
            SsaOp::Call { dest, args, .. } | SsaOp::CallVirt { dest, args, .. } => {
                (*dest, args.clone())
            }
            _ => return false,
        };

        // Remap arguments
        let mut remapped_args = Vec::with_capacity(arg_mapping.len());
        for &param_idx in arg_mapping {
            if let Some(&arg) = original_args.get(param_idx) {
                remapped_args.push(arg);
            } else {
                return false;
            }
        }

        // Create the new call operation
        let new_op = if is_virtual {
            SsaOp::CallVirt {
                dest,
                method: *target_method,
                args: remapped_args,
            }
        } else {
            SsaOp::Call {
                dest,
                method: *target_method,
                args: remapped_args,
            }
        };

        // Replace the instruction
        if let Some(block) = self.caller_ssa.block_mut(call_block_idx) {
            block.instructions_mut()[call_instr_idx].set_op(new_op);
            self.changes
                .record(EventKind::MethodInlined)
                .at(self.caller_token, call_instr_idx)
                .message(format!(
                    "devirtualized proxy {:?} -> {:?}",
                    proxy_token,
                    target_method.token()
                ));
            return true;
        }

        false
    }

    /// Eliminates a call to a void no-op method.
    ///
    /// Replaces the call instruction with a Nop, which will be cleaned up by
    /// the dead code elimination pass.
    ///
    /// # Arguments
    ///
    /// * `call_block_idx` - Block index of the call instruction.
    /// * `call_instr_idx` - Instruction index within the block.
    /// * `call_op` - The call operation being eliminated.
    /// * `callee_token` - Token of the no-op method (for logging).
    ///
    /// # Returns
    ///
    /// `true` if elimination was successful.
    fn eliminate_noop_call(
        &mut self,
        call_block_idx: usize,
        call_instr_idx: usize,
        call_op: &SsaOp,
        callee_token: Token,
    ) -> bool {
        if !matches!(call_op, SsaOp::Call { .. } | SsaOp::CallVirt { .. }) {
            return false;
        }

        if let Some(block) = self.caller_ssa.block_mut(call_block_idx) {
            if let Some(instr) = block.instructions_mut().get_mut(call_instr_idx) {
                instr.set_op(SsaOp::Nop);
                self.changes
                    .record(EventKind::MethodInlined)
                    .at(self.caller_token, call_instr_idx)
                    .message(format!(
                        "eliminated no-op call to 0x{:08x}",
                        callee_token.value()
                    ));
                return true;
            }
        }
        false
    }

    /// Folds a call to a constant-returning method into the constant value.
    ///
    /// Replaces the call instruction with a Const instruction that produces
    /// the same value the method would have returned. If the return value is
    /// unused, replaces with Nop instead.
    ///
    /// # Arguments
    ///
    /// * `call_block_idx` - Block index of the call instruction.
    /// * `call_instr_idx` - Instruction index within the block.
    /// * `call_op` - The call operation being folded.
    /// * `const_val` - The constant value to fold to.
    /// * `callee_token` - Token of the constant-returning method (for logging).
    ///
    /// # Returns
    ///
    /// `true` if folding was successful.
    fn fold_constant_call(
        &mut self,
        call_block_idx: usize,
        call_instr_idx: usize,
        call_op: &SsaOp,
        const_val: &ConstValue,
        callee_token: Token,
    ) -> bool {
        let dest = match call_op {
            SsaOp::Call { dest, .. } | SsaOp::CallVirt { dest, .. } => *dest,
            _ => return false,
        };

        if let Some(dest_var) = dest {
            if let Some(block) = self.caller_ssa.block_mut(call_block_idx) {
                if let Some(instr) = block.instructions_mut().get_mut(call_instr_idx) {
                    instr.set_op(SsaOp::Const {
                        dest: dest_var,
                        value: const_val.clone(),
                    });
                    self.changes
                        .record(EventKind::MethodInlined)
                        .at(self.caller_token, call_instr_idx)
                        .message(format!(
                            "folded constant call to 0x{:08x} -> {:?}",
                            callee_token.value(),
                            const_val
                        ));
                    return true;
                }
            }
        } else {
            // No destination - just replace with Nop
            if let Some(block) = self.caller_ssa.block_mut(call_block_idx) {
                if let Some(instr) = block.instructions_mut().get_mut(call_instr_idx) {
                    instr.set_op(SsaOp::Nop);
                    self.changes
                        .record(EventKind::MethodInlined)
                        .at(self.caller_token, call_instr_idx)
                        .message(format!(
                            "eliminated unused constant call to 0x{:08x}",
                            callee_token.value()
                        ));
                    return true;
                }
            }
        }
        false
    }

    /// Remaps variables in an SSA operation using the given mapping.
    ///
    /// Creates fresh variables in the caller for any callee variables not
    /// already in the mapping (i.e., variables defined within the callee).
    ///
    /// # Arguments
    ///
    /// * `op` - The SSA operation to remap.
    /// * `var_remap` - Mapping from callee variables to caller variables.
    /// * `callee_ssa` - The callee's SSA (for variable metadata).
    /// * `caller_ssa` - The caller's SSA (for creating new variables).
    ///
    /// # Returns
    ///
    /// A cloned operation with all variables remapped to caller variables.
    fn remap_op(
        op: &SsaOp,
        var_remap: &mut HashMap<SsaVarId, SsaVarId>,
        callee_ssa: &SsaFunction,
        caller_ssa: &mut SsaFunction,
    ) -> SsaOp {
        let mut cloned = op.clone();

        // Remap destination
        if let Some(dest) = cloned.dest() {
            let new_dest = Self::get_or_create_var(dest, var_remap, callee_ssa, caller_ssa);
            cloned.set_dest(new_dest);
        }

        // Remap uses
        for used in op.uses() {
            let new_var = var_remap.get(&used).copied().unwrap_or(used);
            cloned.replace_uses(used, new_var);
        }

        cloned
    }

    /// Gets the remapped variable or creates a new one in the caller.
    ///
    /// When creating a new variable, copies the metadata from the callee's
    /// variable to ensure proper type information. The new variable is
    /// registered as a stack temporary in the caller.
    ///
    /// # Arguments
    ///
    /// * `var` - The callee variable to look up or create.
    /// * `var_remap` - Mapping from callee variables to caller variables.
    /// * `callee_ssa` - The callee's SSA (for variable metadata).
    /// * `caller_ssa` - The caller's SSA (for creating new variables).
    ///
    /// # Returns
    ///
    /// The remapped variable ID in the caller's SSA.
    fn get_or_create_var(
        var: SsaVarId,
        var_remap: &mut HashMap<SsaVarId, SsaVarId>,
        callee_ssa: &SsaFunction,
        caller_ssa: &mut SsaFunction,
    ) -> SsaVarId {
        if let Some(&remapped) = var_remap.get(&var) {
            return remapped;
        }

        let new_id = if let Some(callee_var) = callee_ssa.variable(var) {
            let new_var = SsaVariable::new_typed(
                VariableOrigin::Stack(caller_ssa.variable_count() as u32),
                0,
                DefSite::instruction(0, 0),
                callee_var.var_type().clone(),
            );
            caller_ssa.add_variable(new_var)
        } else {
            let new_var = SsaVariable::new(
                VariableOrigin::Stack(caller_ssa.variable_count() as u32),
                0,
                DefSite::instruction(0, 0),
            );
            caller_ssa.add_variable(new_var)
        };

        var_remap.insert(var, new_id);
        new_id
    }
}

/// Pass that inlines small, pure methods at their call sites.
///
/// This pass operates on a per-method basis but consults the global context
/// to access callee method SSA forms. It identifies call sites where the
/// callee is small and pure, then replaces the call with the inlined body.
#[derive(Debug, Default)]
pub struct InliningPass {
    /// Maximum instruction count for inlining candidates.
    inline_threshold: usize,
}

impl InliningPass {
    /// Creates a new inlining pass with default threshold (20 instructions).
    #[must_use]
    pub fn new() -> Self {
        Self {
            inline_threshold: 20,
        }
    }

    /// Creates a new inlining pass with a custom threshold.
    ///
    /// # Arguments
    ///
    /// * `threshold` - Maximum instruction count for methods to be inlined.
    #[must_use]
    pub fn with_threshold(threshold: usize) -> Self {
        Self {
            inline_threshold: threshold,
        }
    }

    /// Finds the argument index that a variable ultimately comes from.
    ///
    /// This traces through:
    /// 1. Direct argument variables (VariableOrigin::Argument)
    /// 2. Variables defined by LoadArg instructions
    /// 3. Variables defined by Copy from arguments
    fn find_argument_origin(
        ssa: &SsaFunction,
        var: SsaVarId,
        instructions: &[SsaInstruction],
    ) -> Option<usize> {
        // First, check if the variable directly represents an argument
        if let Some(var_info) = ssa.variable(var) {
            if let VariableOrigin::Argument(idx) = var_info.origin() {
                return Some(idx as usize);
            }
        }

        // Check if this variable was defined by a LoadArg or Copy instruction
        for instr in instructions {
            match instr.op() {
                SsaOp::LoadArg { dest, arg_index } if *dest == var => {
                    return Some(*arg_index as usize);
                }
                SsaOp::Copy { dest, src } if *dest == var => {
                    return Self::find_argument_origin(ssa, *src, instructions);
                }
                _ => {}
            }
        }

        None
    }

    /// Detects if a method is a simple proxy that just forwards to another method.
    ///
    /// A proxy method:
    /// 1. Has a single basic block
    /// 2. Contains exactly one Call/CallVirt instruction
    /// 3. All call arguments come directly from method parameters
    /// 4. If non-void, returns the call result directly
    /// 5. Has no other instructions besides parameter loads, the call, and return
    ///
    /// # Returns
    ///
    /// If this is a proxy, returns `Some((target_method, arg_mapping, is_virtual))` where:
    /// - `target_method` is the forwarding target
    /// - `arg_mapping` maps caller argument index to callee parameter index
    /// - `is_virtual` indicates if the forwarded call is virtual
    fn detect_proxy_pattern(ssa: &SsaFunction) -> Option<(MethodRef, Vec<usize>, bool)> {
        // Must be single-block method
        if ssa.blocks().len() != 1 {
            return None;
        }

        let block = ssa.blocks().first()?;
        let instructions = block.instructions();

        // Find the call instruction
        let mut call_info: Option<(&MethodRef, &[SsaVarId], Option<SsaVarId>, bool)> = None;
        let mut call_count = 0;

        for instr in instructions {
            match instr.op() {
                SsaOp::Call { method, args, dest } => {
                    call_count += 1;
                    call_info = Some((method, args, *dest, false));
                }
                SsaOp::CallVirt { method, args, dest } => {
                    call_count += 1;
                    call_info = Some((method, args, *dest, true));
                }
                // These are allowed in proxy methods
                SsaOp::Return { .. }
                | SsaOp::Nop
                | SsaOp::Phi { .. }
                | SsaOp::LoadArg { .. }
                | SsaOp::LoadLocal { .. }
                | SsaOp::Copy { .. } => {}
                // Any other instruction disqualifies as a proxy
                _ => return None,
            }
        }

        // Must have exactly one call
        if call_count != 1 {
            return None;
        }

        let (target_method, call_args, call_dest, is_virtual) = call_info?;

        // Build parameter mapping
        let mut arg_mapping = Vec::with_capacity(call_args.len());
        let num_params = ssa.num_args();

        for &arg_var in call_args {
            let param_idx = Self::find_argument_origin(ssa, arg_var, instructions);

            match param_idx {
                Some(idx) if idx < num_params => {
                    arg_mapping.push(idx);
                }
                _ => {
                    return None;
                }
            }
        }

        // Check that if there's a return, it returns the call result
        for instr in instructions {
            if let SsaOp::Return {
                value: Some(ret_var),
            } = instr.op()
            {
                if Some(*ret_var) != call_dest {
                    return None;
                }
            }
        }

        Some((*target_method, arg_mapping, is_virtual))
    }
}

impl SsaPass for InliningPass {
    fn name(&self) -> &'static str {
        "InliningPass"
    }

    fn description(&self) -> &'static str {
        "Inlines small, pure methods and devirtualizes proxy calls"
    }

    fn run_on_method(
        &self,
        ssa: &mut SsaFunction,
        method_token: Token,
        ctx: &CompilerContext,
        assembly: &Arc<CilObject>,
    ) -> Result<bool> {
        // Create method-specific inlining context
        let mut inline_ctx = InliningContext::new(self, ssa, method_token, ctx, assembly);

        // Find all candidates
        let candidates = inline_ctx.find_candidates();
        if candidates.is_empty() {
            return Ok(false);
        }

        // Process candidates in reverse order to maintain valid indices
        for candidate in candidates.into_iter().rev() {
            inline_ctx.process_candidate(&candidate);
        }

        // Merge changes back to the analysis context
        let changed = inline_ctx.has_changes();
        if changed {
            ctx.events.merge(inline_ctx.into_changes());
        }
        Ok(changed)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{
        analysis::{CallGraph, ConstValue, MethodRef, SsaFunctionBuilder, SsaOp, SsaVarId},
        compiler::CompilerContext,
        compiler::{
            passes::inlining::{InliningContext, InliningPass},
            SsaPass,
        },
        metadata::token::Token,
        test::helpers::test_assembly_arc,
        CilObject,
    };

    fn test_context() -> CompilerContext {
        CompilerContext::new(Arc::new(CallGraph::new()))
    }

    /// Returns a cached test assembly for use in tests.
    fn test_assembly() -> Arc<CilObject> {
        test_assembly_arc()
    }

    #[test]
    fn test_pass_creation() {
        let pass = InliningPass::new();
        assert_eq!(pass.name(), "InliningPass");
        assert_eq!(pass.inline_threshold, 20);

        let pass_custom = InliningPass::with_threshold(50);
        assert_eq!(pass_custom.inline_threshold, 50);
    }

    #[test]
    fn test_inline_constant_return() {
        // Callee: returns constant 42
        let callee_token = Token::new(0x06000002);
        let (callee_ssa, callee_v0) = {
            let mut v0_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
                f.block(0, |b| {
                    let v0 = b.const_i32(42);
                    v0_out = v0;
                    b.ret_val(v0);
                });
            });
            (ssa, v0_out)
        };

        // Caller: calls callee
        let caller_token = Token::new(0x06000001);
        let (mut caller_ssa, call_dest) = {
            let mut dest_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
                f.block(0, |b| {
                    let dest = b.call(MethodRef::new(callee_token), &[]);
                    dest_out = dest;
                    b.ret_val(dest);
                });
            });
            (ssa, dest_out)
        };

        // Set up context
        let ctx = test_context();
        ctx.set_ssa(callee_token, callee_ssa.clone());

        // Get the call op before creating context (need to borrow caller_ssa)
        let call_op = caller_ssa.block(0).unwrap().instructions()[0].op().clone();

        // Create inlining context and inline
        let pass = InliningPass::new();
        let assembly = test_assembly();
        let mut inline_ctx =
            InliningContext::new(&pass, &mut caller_ssa, caller_token, &ctx, &assembly);
        let result = inline_ctx.inline_call(&callee_ssa, 0, 0, &call_op, callee_token);

        assert!(result, "Inlining should succeed");

        // Check that the call was replaced with a constant
        let block = inline_ctx.caller_ssa.block(0).unwrap();
        let first_instr = &block.instructions()[0];
        match first_instr.op() {
            SsaOp::Const { dest, value } => {
                assert_eq!(*dest, call_dest);
                assert_eq!(*value, ConstValue::I32(42));
            }
            other => panic!("Expected Const, got {:?}", other),
        }

        // Verify the callee's const was created correctly
        let _ = callee_v0;
    }

    #[test]
    fn test_inline_void_pure() {
        // Callee: void method that does nothing impure
        let callee_token = Token::new(0x06000002);
        let callee_ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
            f.block(0, |b| b.ret());
        });

        // Caller: calls callee
        let caller_token = Token::new(0x06000001);
        let mut caller_ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
            f.block(0, |b| {
                b.call_void(MethodRef::new(callee_token), &[]);
                b.ret();
            });
        });

        // Set up context
        let ctx = test_context();
        ctx.set_ssa(callee_token, callee_ssa.clone());

        // Get the call op before creating context
        let call_op = caller_ssa.block(0).unwrap().instructions()[0].op().clone();

        // Create inlining context and inline
        let pass = InliningPass::new();
        let assembly = test_assembly();
        let mut inline_ctx =
            InliningContext::new(&pass, &mut caller_ssa, caller_token, &ctx, &assembly);
        let result = inline_ctx.inline_call(&callee_ssa, 0, 0, &call_op, callee_token);

        assert!(result, "Inlining should succeed");

        // Check that the call was replaced with Nop
        let block = inline_ctx.caller_ssa.block(0).unwrap();
        let first_instr = &block.instructions()[0];
        assert!(
            matches!(first_instr.op(), SsaOp::Nop),
            "Expected Nop, got {:?}",
            first_instr.op()
        );
    }

    #[test]
    fn test_no_inline_self_recursion() {
        let pass = InliningPass::new();
        let token = Token::new(0x06000001);
        let ctx = test_context();
        let assembly = test_assembly();

        // Create a dummy SSA for the context
        let mut dummy_ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
            f.block(0, |b| b.ret());
        });

        let inline_ctx = InliningContext::new(&pass, &mut dummy_ssa, token, &ctx, &assembly);

        // Self-recursion check - is_valid_target returns false for self
        assert!(!inline_ctx.is_valid_target(token));
    }

    #[test]
    fn test_no_inline_large_method() {
        let callee_token = Token::new(0x06000002);
        let caller_token = Token::new(0x06000001);

        // Create a callee with many instructions (> threshold)
        let callee_ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
            f.block(0, |b| {
                for _ in 0..30 {
                    let _ = b.const_i32(0);
                }
                b.ret();
            });
        });

        let ctx = test_context();
        ctx.set_ssa(callee_token, callee_ssa);

        let pass = InliningPass::new(); // threshold = 20
        let assembly = test_assembly();

        // Create a dummy caller SSA
        let mut caller_ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
            f.block(0, |b| b.ret());
        });

        let inline_ctx =
            InliningContext::new(&pass, &mut caller_ssa, caller_token, &ctx, &assembly);
        assert!(!inline_ctx.should_inline(callee_token));
    }

    #[test]
    fn test_inline_full_computation() {
        // Callee: returns arg0 + 10
        // This is a PureComputation that requires full inlining
        let callee_token = Token::new(0x06000002);
        let callee_ssa = SsaFunctionBuilder::new(1, 0).build_with(|f| {
            let param0 = f.arg(0);
            f.block(0, |b| {
                let v1 = b.const_i32(10);
                let v2 = b.add(param0, v1);
                b.ret_val(v2);
            });
        });

        // Caller: calls callee with v0=5, stores result in v3
        let caller_token = Token::new(0x06000001);
        let mut caller_ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
            f.block(0, |b| {
                let v0 = b.const_i32(5);
                let v1 = b.call(MethodRef::new(callee_token), &[v0]);
                b.ret_val(v1);
            });
        });

        // Set up context
        let ctx = test_context();
        ctx.set_ssa(callee_token, callee_ssa.clone());

        // Get the call op before creating context
        let call_op = caller_ssa.block(0).unwrap().instructions()[1].op().clone();

        // Create inlining context and inline
        let pass = InliningPass::new();
        let assembly = test_assembly();
        let mut inline_ctx =
            InliningContext::new(&pass, &mut caller_ssa, caller_token, &ctx, &assembly);
        let result = inline_ctx.inline_call(&callee_ssa, 0, 1, &call_op, callee_token);

        assert!(result, "Full inlining should succeed");

        // Verify the caller now has more instructions
        let block = inline_ctx.caller_ssa.block(0).unwrap();
        assert!(
            block.instructions().len() > 3,
            "Expected inlined instructions, got {} instructions",
            block.instructions().len()
        );

        // Check that the second instruction is now the inlined const 10
        let second_instr = &block.instructions()[1];
        match second_instr.op() {
            SsaOp::Const { value, .. } => {
                assert_eq!(*value, ConstValue::I32(10), "Expected inlined constant 10");
            }
            other => panic!("Expected Const for inlined instruction, got {:?}", other),
        }

        // Check that there's an Add instruction
        let has_add = block
            .instructions()
            .iter()
            .any(|i| matches!(i.op(), SsaOp::Add { .. }));
        assert!(has_add, "Expected Add instruction after inlining");
    }

    #[test]
    fn test_detect_proxy_void() {
        // Proxy: void method that forwards to Console.WriteLine(string)
        // void proxy(string s) { Console.WriteLine(s); }
        let target_token = Token::new(0x0A000001); // External method

        let proxy_ssa = SsaFunctionBuilder::new(1, 0).build_with(|f| {
            let param0 = f.arg(0);
            f.block(0, |b| {
                b.call_void(MethodRef::new(target_token), &[param0]);
                b.ret();
            });
        });

        // Should detect this as a proxy
        let result = InliningPass::detect_proxy_pattern(&proxy_ssa);
        assert!(result.is_some(), "Should detect void proxy");

        let (target, arg_mapping, is_virtual) = result.unwrap();
        assert_eq!(target.token(), target_token);
        assert_eq!(arg_mapping, vec![0]); // First arg maps to param 0
        assert!(!is_virtual);
    }

    #[test]
    fn test_detect_proxy_with_return() {
        // Proxy: string method that forwards to String.Format
        // string proxy(string fmt, object arg) { return String.Format(fmt, arg); }
        let target_token = Token::new(0x0A000002);

        let proxy_ssa = SsaFunctionBuilder::new(2, 0).build_with(|f| {
            let param0 = f.arg(0);
            let param1 = f.arg(1);
            f.block(0, |b| {
                let result = b.call(MethodRef::new(target_token), &[param0, param1]);
                b.ret_val(result);
            });
        });

        let result = InliningPass::detect_proxy_pattern(&proxy_ssa);
        assert!(result.is_some(), "Should detect proxy with return");

        let (target, arg_mapping, is_virtual) = result.unwrap();
        assert_eq!(target.token(), target_token);
        assert_eq!(arg_mapping, vec![0, 1]);
        assert!(!is_virtual);
    }

    #[test]
    fn test_detect_proxy_reordered_args() {
        // Proxy: reorders arguments
        // int proxy(int a, int b) { return target(b, a); }
        let target_token = Token::new(0x0A000003);

        let proxy_ssa = SsaFunctionBuilder::new(2, 0).build_with(|f| {
            let param0 = f.arg(0);
            let param1 = f.arg(1);
            f.block(0, |b| {
                // Pass args in reverse order
                let result = b.call(MethodRef::new(target_token), &[param1, param0]);
                b.ret_val(result);
            });
        });

        let result = InliningPass::detect_proxy_pattern(&proxy_ssa);
        assert!(result.is_some(), "Should detect proxy with reordered args");

        let (target, arg_mapping, is_virtual) = result.unwrap();
        assert_eq!(target.token(), target_token);
        assert_eq!(arg_mapping, vec![1, 0]); // Reversed
        assert!(!is_virtual);
    }

    #[test]
    fn test_not_proxy_with_computation() {
        // Not a proxy: adds a constant before calling
        // int notProxy(int a) { return target(a + 1); }
        let target_token = Token::new(0x0A000004);

        let not_proxy_ssa = SsaFunctionBuilder::new(1, 0).build_with(|f| {
            let param0 = f.arg(0);
            f.block(0, |b| {
                let one = b.const_i32(1);
                let sum = b.add(param0, one);
                let result = b.call(MethodRef::new(target_token), &[sum]);
                b.ret_val(result);
            });
        });

        let result = InliningPass::detect_proxy_pattern(&not_proxy_ssa);
        assert!(
            result.is_none(),
            "Should NOT detect as proxy - has computation"
        );
    }

    #[test]
    fn test_devirtualize_proxy() {
        // Setup: caller calls proxy, proxy forwards to target
        let proxy_token = Token::new(0x06000002);
        let target_token = Token::new(0x0A000001);

        // Proxy: forwards arg0 to target
        let proxy_ssa = SsaFunctionBuilder::new(1, 0).build_with(|f| {
            let param0 = f.arg(0);
            f.block(0, |b| {
                b.call_void(MethodRef::new(target_token), &[param0]);
                b.ret();
            });
        });

        // Caller: calls proxy
        let caller_token = Token::new(0x06000001);
        let mut caller_ssa = SsaFunctionBuilder::new(1, 0).build_with(|f| {
            let arg0 = f.arg(0);
            f.block(0, |b| {
                b.call_void(MethodRef::new(proxy_token), &[arg0]);
                b.ret();
            });
        });

        let ctx = test_context();
        ctx.set_ssa(proxy_token, proxy_ssa);

        // Get the proxy pattern
        let proxy_pattern = ctx
            .with_ssa(proxy_token, InliningPass::detect_proxy_pattern)
            .flatten();
        assert!(proxy_pattern.is_some(), "Proxy should be detected");

        let (target_method, arg_mapping, is_virtual) = proxy_pattern.unwrap();

        // Get call_op before creating context
        let call_op = caller_ssa.block(0).unwrap().instructions()[0].op().clone();

        // Devirtualize using InliningContext
        let pass = InliningPass::new();
        let assembly = test_assembly();
        let mut inline_ctx =
            InliningContext::new(&pass, &mut caller_ssa, caller_token, &ctx, &assembly);
        let result = inline_ctx.devirtualize_proxy(
            0,
            0,
            &call_op,
            &target_method,
            &arg_mapping,
            is_virtual,
            proxy_token,
        );

        assert!(result, "Devirtualization should succeed");

        // Check that the call target changed
        let block = inline_ctx.caller_ssa.block(0).unwrap();
        let first_instr = &block.instructions()[0];
        match first_instr.op() {
            SsaOp::Call { method, .. } => {
                assert_eq!(
                    method.token(),
                    target_token,
                    "Call should now target {:?}",
                    target_token
                );
            }
            other => panic!("Expected Call, got {:?}", other),
        }
    }
}
