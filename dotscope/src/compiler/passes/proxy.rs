//! Proxy devirtualization and no-op elimination pass.
//!
//! This pass detects single-call forwarder methods (proxies) and retargets their
//! callers to invoke the forwarding target directly, eliminating the proxy
//! overhead. It also detects no-op methods (methods that just return or return a
//! constant) and replaces calls to them with the appropriate constant or nop.
//!
//! # Proxy Detection
//!
//! A proxy method is one that:
//! 1. Has a single basic block
//! 2. Contains exactly one `Call`/`CallVirt` instruction
//! 3. Forwards parameters directly as arguments (possibly reordered)
//! 4. Returns the call result (if non-void)
//! 5. Has no other side effects besides the forwarded call
//!
//! When a proxy is detected, the call at the caller site is replaced with a
//! direct call to the forwarding target, eliminating the wrapper method.
//!
//! # No-Op Elimination
//!
//! A no-op method is one that:
//! - Just returns (void method with only `ret`)
//! - Always returns a constant value
//! - Has no side effects (is pure)
//!
//! Calls to such methods are replaced with `Nop` (void) or `Const` (constant
//! return), removing unnecessary call overhead.
//!
//! # Safety
//!
//! Proxy devirtualization is always safe because the forwarded call happens
//! exactly once in either case -- we are just eliminating the wrapper.
//!
//! No-op elimination is safe because pure methods with no observable side
//! effects can be elided without changing program semantics.
//!
//! # Pipeline Position
//!
//! This pass runs in the **normalize** phase so it is always active regardless
//! of whether full method inlining is enabled. Running before dead method
//! elimination ensures that after proxy retargeting the wrapper methods have
//! zero callers and can be eliminated.

use crate::{
    analysis::{
        ConstValue, DefSite, MethodRef, ReturnInfo, SsaFunction, SsaInstruction, SsaOp, SsaVarId,
        VariableOrigin,
    },
    compiler::{CompilerContext, EventKind, EventLog, ModificationScope, PassCapability, SsaPass},
    metadata::{tables::MemberRefSignature, token::Token, typesystem::CilTypeReference},
    CilObject, Result,
};

/// How the proxy method forwards to its target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardKind {
    /// Direct call: `call <target>`
    Call,
    /// Virtual call: `callvirt <target>`
    CallVirt,
    /// Constructor call: `newobj <ctor>` — factory proxy returning a new object.
    NewObj,
}

/// Source of an argument in a proxy forwarding pattern.
#[derive(Debug, Clone, PartialEq)]
pub enum ProxyArgSource {
    /// Forwarded from a method parameter (by parameter index).
    Parameter(usize),
    /// Injected constant value (e.g., decrypted string from obfuscator).
    Constant(ConstValue),
}

/// Action to take at a call site.
#[derive(Debug, Clone)]
enum ProxyAction {
    /// Proxy devirtualization: replace call target with forwarding target.
    Devirtualize {
        target_method: MethodRef,
        arg_sources: Vec<ProxyArgSource>,
        kind: ForwardKind,
    },
    /// No-op elimination: remove the call entirely (void method that just returns).
    NoOpEliminate,
    /// Constant fold: replace the call with a constant value.
    ConstantFold(ConstValue),
}

/// A candidate call site for devirtualization or elimination.
#[derive(Debug, Clone)]
struct ProxyCandidate {
    /// Block index containing the call.
    block_idx: usize,
    /// Instruction index within the block.
    instr_idx: usize,
    /// Token of the method being called (the callee/proxy).
    callee_token: Token,
    /// What action to take at this call site.
    action: ProxyAction,
}

/// Pass that devirtualizes proxy methods and eliminates no-op calls.
///
/// This pass runs in the normalize phase and is always enabled. It examines
/// each call site, looks up the callee's SSA from `CompilerContext::ssa_functions`,
/// and determines whether the callee is a simple forwarder or a no-op. If so,
/// the call is rewritten in place.
#[derive(Debug, Default)]
pub struct ProxyDevirtualizationPass;

impl ProxyDevirtualizationPass {
    /// Creates a new proxy devirtualization pass.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Detects if a method is a simple proxy that just forwards to another method.
    ///
    /// A proxy method:
    /// 1. Has a single basic block
    /// 2. Contains exactly one `Call`/`CallVirt`/`NewObj` instruction
    /// 3. All call arguments come directly from method parameters
    /// 4. If non-void, returns the call result directly
    /// 5. Has no other instructions besides parameter loads, the call, and return
    ///
    /// # Returns
    ///
    /// If this is a proxy, returns `Some((target_method, arg_mapping, kind))` where:
    /// - `target_method` is the forwarding target
    /// - `arg_mapping` maps caller argument index to callee parameter index
    /// - `kind` indicates Call, CallVirt, or NewObj forwarding
    pub fn detect_proxy_pattern(
        ssa: &SsaFunction,
    ) -> Option<(MethodRef, Vec<ProxyArgSource>, ForwardKind)> {
        // Find the "real" block — the one with actual instructions (not just jumps).
        // CFF-unflattened proxy stubs may have multiple blocks where all but one
        // are empty trampolines (single Jump instruction). Block merging may not
        // have collapsed them yet.
        let block = if ssa.blocks().len() == 1 {
            ssa.blocks().first()?
        } else {
            // Find the block that has the call + return. Skip blocks that are
            // just unconditional jumps (trampolines from CFF reconstruction).
            let mut candidate = None;
            for block in ssa.blocks() {
                let instrs = block.instructions();
                // A trampoline block contains only jumps and nops
                let is_trampoline = instrs.is_empty()
                    || instrs
                        .iter()
                        .all(|i| matches!(i.op(), SsaOp::Jump { .. } | SsaOp::Nop));
                if !is_trampoline {
                    if candidate.is_some() {
                        // Multiple non-trampoline blocks → not a proxy
                        return None;
                    }
                    candidate = Some(block);
                }
            }
            candidate?
        };

        let instructions = block.instructions();

        // Find the call instruction (Call, CallVirt, or NewObj)
        let mut call_info: Option<(&MethodRef, &[SsaVarId], Option<SsaVarId>, ForwardKind)> = None;
        let mut call_count = 0;

        for instr in instructions {
            match instr.op() {
                SsaOp::Call { method, args, dest } => {
                    call_count += 1;
                    call_info = Some((method, args, *dest, ForwardKind::Call));
                }
                SsaOp::CallVirt { method, args, dest } => {
                    call_count += 1;
                    call_info = Some((method, args, *dest, ForwardKind::CallVirt));
                }
                SsaOp::NewObj { ctor, args, dest } => {
                    call_count += 1;
                    call_info = Some((ctor, args, Some(*dest), ForwardKind::NewObj));
                }
                // These are allowed in proxy methods
                SsaOp::Return { .. }
                | SsaOp::Nop
                | SsaOp::Phi { .. }
                | SsaOp::LoadArg { .. }
                | SsaOp::LoadLocal { .. }
                | SsaOp::Copy { .. }
                | SsaOp::Const { .. } => {}
                // Any other instruction disqualifies as a proxy
                _ => return None,
            }
        }

        // Must have exactly one call
        if call_count != 1 {
            return None;
        }

        let (target_method, call_args, call_dest, kind) = call_info?;

        // Build argument source mapping (parameters and/or constants)
        let mut arg_sources = Vec::with_capacity(call_args.len());
        let num_params = ssa.num_args();

        for &arg_var in call_args {
            // Try parameter origin first
            let param_idx = Self::find_argument_origin(ssa, arg_var, instructions);
            if let Some(idx) = param_idx {
                if idx < num_params {
                    arg_sources.push(ProxyArgSource::Parameter(idx));
                    continue;
                }
            }

            // Try constant origin — handles obfuscator-injected constants
            // (e.g., decrypted strings passed as extra arguments)
            if let Some(const_val) = Self::find_constant_origin(arg_var, instructions) {
                arg_sources.push(ProxyArgSource::Constant(const_val));
                continue;
            }

            // Neither parameter nor constant → not a proxy
            return None;
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

        Some((*target_method, arg_sources, kind))
    }

    /// Finds the argument index that a variable ultimately comes from.
    ///
    /// This traces through:
    /// 1. Direct argument variables (`VariableOrigin::Argument`)
    /// 2. Variables defined by `LoadArg` instructions
    /// 3. Variables defined by `Copy` from arguments
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

    /// Finds the constant value that a variable ultimately comes from.
    ///
    /// Traces through `Copy` chains to find a `Const` instruction defining
    /// the variable. Returns `None` if the variable doesn't originate from
    /// a constant.
    fn find_constant_origin(var: SsaVarId, instructions: &[SsaInstruction]) -> Option<ConstValue> {
        // Check if the variable is directly defined by a Const instruction
        for instr in instructions {
            match instr.op() {
                SsaOp::Const { dest, value } if *dest == var => {
                    return Some(value.clone());
                }
                SsaOp::Copy { dest, src } if *dest == var => {
                    return Self::find_constant_origin(*src, instructions);
                }
                _ => {}
            }
        }

        None
    }

    /// Checks if a callee token is a valid target for devirtualization.
    fn is_valid_target(callee_token: Token, caller_token: Token, ctx: &CompilerContext) -> bool {
        // Don't retarget self-recursion
        if callee_token == caller_token {
            return false;
        }

        // Don't retarget methods marked as non-inlinable (decryptors, dispatchers, etc.)
        if ctx.no_inline.contains(&callee_token) {
            return false;
        }

        true
    }

    /// Resolves a token to its MethodDef equivalent.
    ///
    /// SSA forms are stored under MethodDef tokens, but call instructions may
    /// use MemberRef tokens for internal methods. This resolves
    /// MemberRef -> MethodDef so we can look up the callee's SSA.
    fn resolve_to_method_def(token: Token, assembly: &CilObject) -> Token {
        let table_id = token.table();

        // Already a MethodDef - return as-is
        if table_id == 0x06 {
            return token;
        }

        // MemberRef - try to resolve to MethodDef
        if table_id == 0x0A {
            let refs = assembly.refs_members();
            if let Some(member_ref_entry) = refs.get(&token) {
                let member_ref = member_ref_entry.value();

                // Only handle method signatures, not fields
                let MemberRefSignature::Method(ref _method_sig) = member_ref.signature else {
                    return token;
                };

                // Check if declared by an internal type. Try TypeDef first,
                // then TypeRef (ConfuserEx creates fake assembly references so
                // internal MemberRefs appear external — the TypeRef may still
                // resolve to an internal TypeDef via the weak reference).
                let resolved_type = match &member_ref.declaredby {
                    CilTypeReference::TypeDef(r) | CilTypeReference::TypeRef(r) => r.upgrade(),
                    _ => None,
                };
                if let Some(type_info) = resolved_type {
                    if let Some(method) = type_info
                        .query_methods()
                        .name(&member_ref.name)
                        .find_first()
                    {
                        return method.token;
                    }
                }

                // Fallback: scan all methods by name. Handles cases where the
                // MemberRef's TypeRef points to a fake assembly that can't be
                // resolved to a TypeDef (e.g., ConfuserEx proxy protection).
                for entry in assembly.methods().iter() {
                    let method_token = *entry.key();
                    if let Some(name) = assembly.resolve_method_name(method_token) {
                        if name == member_ref.name {
                            return method_token;
                        }
                    }
                }
            }
        }

        token
    }

    /// Checks if a method should be devirtualized as a proxy.
    fn should_devirtualize_proxy(
        callee_token: Token,
        caller_token: Token,
        ctx: &CompilerContext,
        assembly: &CilObject,
    ) -> Option<(MethodRef, Vec<ProxyArgSource>, ForwardKind)> {
        // Don't retarget self-recursion
        if callee_token == caller_token {
            return None;
        }

        // Skip constructors — a default .ctor (ldarg.0; call base.ctor; ret)
        // matches the proxy pattern but is NOT a proxy stub.
        if let Some(name) = assembly.resolve_method_name(callee_token) {
            if name == ".ctor" || name == ".cctor" {
                return None;
            }
        }

        // Check the callee's live SSA for the proxy forwarding pattern.
        let result = ctx
            .with_ssa(callee_token, |callee_ssa| {
                Self::detect_proxy_pattern(callee_ssa)
            })
            .flatten();

        if result.is_some() {
            return result;
        }

        // For non-proxy methods, respect the no_inline set
        if !Self::is_valid_target(callee_token, caller_token, ctx) {
            return None;
        }

        None
    }

    /// Checks if a method is a no-op that can be eliminated at call sites.
    ///
    /// Returns:
    /// - `Some(None)` - Void no-op: call can be replaced with Nop.
    /// - `Some(Some(ConstValue))` - Constant return: call can be replaced with constant.
    /// - `None` - Not a no-op method.
    // Intentional: None=not noop, Some(None)=void noop, Some(Some(v))=constant noop
    #[allow(clippy::option_option)]
    fn detect_noop_method(
        callee_token: Token,
        caller_token: Token,
        ctx: &CompilerContext,
    ) -> Option<Option<ConstValue>> {
        if !Self::is_valid_target(callee_token, caller_token, ctx) {
            return None;
        }

        ctx.with_ssa(callee_token, |callee_ssa| {
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

    /// Finds all proxy devirtualization and no-op elimination candidates.
    fn find_candidates(
        ssa: &SsaFunction,
        method_token: Token,
        ctx: &CompilerContext,
        assembly: &CilObject,
    ) -> Vec<ProxyCandidate> {
        let mut candidates = Vec::new();

        for (block_idx, instr_idx, instr) in ssa.iter_instructions() {
            let raw_callee_token = match instr.op() {
                SsaOp::Call { method, .. } => method.token(),
                SsaOp::CallVirt { method, .. } => {
                    let token = method.token();
                    // Check if this is actually polymorphic
                    if ctx.call_graph.resolver().is_polymorphic(token) {
                        continue;
                    }
                    token
                }
                _ => continue,
            };

            // Resolve MemberRef tokens to MethodDef tokens for SSA lookup
            let callee_token = Self::resolve_to_method_def(raw_callee_token, assembly);

            // Try no-op elimination first (cheaper check)
            if let Some(noop_result) = Self::detect_noop_method(callee_token, method_token, ctx) {
                let action = match noop_result {
                    None => ProxyAction::NoOpEliminate,
                    Some(val) => ProxyAction::ConstantFold(val),
                };
                candidates.push(ProxyCandidate {
                    block_idx,
                    instr_idx,
                    callee_token,
                    action,
                });
                continue;
            }

            // Try proxy devirtualization
            if let Some((target_method, arg_sources, kind)) =
                Self::should_devirtualize_proxy(callee_token, method_token, ctx, assembly)
            {
                candidates.push(ProxyCandidate {
                    block_idx,
                    instr_idx,
                    callee_token,
                    action: ProxyAction::Devirtualize {
                        target_method,
                        arg_sources,
                        kind,
                    },
                });
            }
        }

        candidates
    }

    /// Processes a single candidate, returning true if the operation was successful.
    fn process_candidate(
        ssa: &mut SsaFunction,
        candidate: &ProxyCandidate,
        method_token: Token,
        ctx: &CompilerContext,
        changes: &mut EventLog,
    ) -> bool {
        let call_op = match ssa.block(candidate.block_idx) {
            Some(block) => match block.instructions().get(candidate.instr_idx) {
                Some(instr) => instr.op().clone(),
                None => return false,
            },
            None => return false,
        };

        let success = match &candidate.action {
            ProxyAction::Devirtualize {
                target_method,
                arg_sources,
                kind,
            } => Self::devirtualize_proxy(
                ssa,
                candidate.block_idx,
                candidate.instr_idx,
                &call_op,
                *target_method,
                arg_sources,
                *kind,
                candidate.callee_token,
                method_token,
                changes,
            ),
            ProxyAction::NoOpEliminate => Self::eliminate_noop_call(
                ssa,
                candidate.block_idx,
                candidate.instr_idx,
                &call_op,
                candidate.callee_token,
                method_token,
                changes,
            ),
            ProxyAction::ConstantFold(const_val) => Self::fold_constant_call(
                ssa,
                candidate.block_idx,
                candidate.instr_idx,
                &call_op,
                const_val,
                candidate.callee_token,
                method_token,
                changes,
            ),
        };

        if success {
            ctx.mark_inlined(candidate.callee_token);
        }
        success
    }

    /// Devirtualizes a proxy call by replacing it with a direct call to the target.
    #[allow(clippy::too_many_arguments)]
    fn devirtualize_proxy(
        ssa: &mut SsaFunction,
        call_block_idx: usize,
        call_instr_idx: usize,
        call_op: &SsaOp,
        target_method: MethodRef,
        arg_sources: &[ProxyArgSource],
        kind: ForwardKind,
        proxy_token: Token,
        caller_token: Token,
        changes: &mut EventLog,
    ) -> bool {
        let (dest, original_args) = match call_op {
            SsaOp::Call { dest, args, .. } | SsaOp::CallVirt { dest, args, .. } => {
                (*dest, args.clone())
            }
            _ => return false,
        };

        // Build arguments for the target call from the proxy's arg sources
        let mut remapped_args = Vec::with_capacity(arg_sources.len());
        let mut const_ops = Vec::new();

        for source in arg_sources {
            match source {
                ProxyArgSource::Parameter(param_idx) => {
                    if let Some(&arg) = original_args.get(*param_idx) {
                        remapped_args.push(arg);
                    } else {
                        return false;
                    }
                }
                ProxyArgSource::Constant(value) => {
                    // Create a new SSA variable for the injected constant
                    let const_var = ssa.create_variable(
                        VariableOrigin::Phi,
                        0,
                        DefSite::instruction(call_block_idx, call_instr_idx),
                        value.ssa_type(),
                    );
                    const_ops.push(SsaOp::Const {
                        dest: const_var,
                        value: value.clone(),
                    });
                    remapped_args.push(const_var);
                }
            }
        }

        // Create the new operation based on the proxy's forwarding kind
        let new_op = match kind {
            ForwardKind::NewObj => {
                // Factory proxy: replace Call with NewObj. The dest must exist
                // since factory proxies always return the new object.
                let Some(dest_var) = dest else {
                    return false;
                };
                SsaOp::NewObj {
                    dest: dest_var,
                    ctor: target_method,
                    args: remapped_args,
                }
            }
            ForwardKind::CallVirt => SsaOp::CallVirt {
                dest,
                method: target_method,
                args: remapped_args,
            },
            ForwardKind::Call => SsaOp::Call {
                dest,
                method: target_method,
                args: remapped_args,
            },
        };

        // Replace the instruction, inserting any constant definitions before the call
        if let Some(block) = ssa.block_mut(call_block_idx) {
            let num_consts = const_ops.len();
            // Insert const instructions before the call site
            let instrs = block.instructions_mut();
            for (i, const_op) in const_ops.into_iter().enumerate() {
                instrs.insert(call_instr_idx + i, SsaInstruction::synthetic(const_op));
            }
            // The call instruction shifted by the number of inserted consts
            instrs[call_instr_idx + num_consts].set_op(new_op);
            changes
                .record(EventKind::MethodInlined)
                .at(caller_token, call_instr_idx)
                .message(format!(
                    "devirtualized proxy {:?} -> {:?}{}",
                    proxy_token,
                    target_method.token(),
                    if kind == ForwardKind::NewObj {
                        " (newobj)"
                    } else {
                        ""
                    }
                ));
            return true;
        }

        false
    }

    /// Eliminates a call to a void no-op method.
    fn eliminate_noop_call(
        ssa: &mut SsaFunction,
        call_block_idx: usize,
        call_instr_idx: usize,
        call_op: &SsaOp,
        callee_token: Token,
        caller_token: Token,
        changes: &mut EventLog,
    ) -> bool {
        if !matches!(call_op, SsaOp::Call { .. } | SsaOp::CallVirt { .. }) {
            return false;
        }

        if let Some(block) = ssa.block_mut(call_block_idx) {
            if let Some(instr) = block.instructions_mut().get_mut(call_instr_idx) {
                instr.set_op(SsaOp::Nop);
                changes
                    .record(EventKind::MethodInlined)
                    .at(caller_token, call_instr_idx)
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
    #[allow(clippy::too_many_arguments)]
    fn fold_constant_call(
        ssa: &mut SsaFunction,
        call_block_idx: usize,
        call_instr_idx: usize,
        call_op: &SsaOp,
        const_val: &ConstValue,
        callee_token: Token,
        caller_token: Token,
        changes: &mut EventLog,
    ) -> bool {
        let dest = match call_op {
            SsaOp::Call { dest, .. } | SsaOp::CallVirt { dest, .. } => *dest,
            _ => return false,
        };

        if let Some(dest_var) = dest {
            if let Some(block) = ssa.block_mut(call_block_idx) {
                if let Some(instr) = block.instructions_mut().get_mut(call_instr_idx) {
                    instr.set_op(SsaOp::Const {
                        dest: dest_var,
                        value: const_val.clone(),
                    });
                    changes
                        .record(EventKind::MethodInlined)
                        .at(caller_token, call_instr_idx)
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
            if let Some(block) = ssa.block_mut(call_block_idx) {
                if let Some(instr) = block.instructions_mut().get_mut(call_instr_idx) {
                    instr.set_op(SsaOp::Nop);
                    changes
                        .record(EventKind::MethodInlined)
                        .at(caller_token, call_instr_idx)
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
}

impl SsaPass for ProxyDevirtualizationPass {
    fn name(&self) -> &'static str {
        "proxy-devirtualization"
    }

    fn description(&self) -> &'static str {
        "Devirtualizes proxy forwarding methods and eliminates no-op calls"
    }

    fn modification_scope(&self) -> ModificationScope {
        ModificationScope::InstructionsOnly
    }

    fn provides(&self) -> &[PassCapability] {
        &[PassCapability::DevirtualizedCalls]
    }

    fn run_on_method(
        &self,
        ssa: &mut SsaFunction,
        method_token: Token,
        ctx: &CompilerContext,
        assembly: &CilObject,
    ) -> Result<bool> {
        let candidates = Self::find_candidates(ssa, method_token, ctx, assembly);
        if candidates.is_empty() {
            return Ok(false);
        }

        let mut changes = EventLog::new();

        // Process candidates in reverse order to maintain valid indices
        for candidate in candidates.into_iter().rev() {
            Self::process_candidate(ssa, &candidate, method_token, ctx, &mut changes);
        }

        let changed = !changes.is_empty();
        if changed {
            ctx.events.merge(&changes);
        }
        Ok(changed)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{
        analysis::{CallGraph, ConstValue, MethodRef, SsaFunctionBuilder, SsaOp, SsaType},
        compiler::{
            passes::proxy::{ForwardKind, ProxyArgSource, ProxyDevirtualizationPass},
            CompilerContext, SsaPass,
        },
        metadata::token::Token,
        test::helpers::test_assembly_arc,
        CilObject,
    };

    fn test_context() -> CompilerContext {
        CompilerContext::new(Arc::new(CallGraph::new()))
    }

    fn test_assembly() -> Arc<CilObject> {
        test_assembly_arc()
    }

    #[test]
    fn test_pass_metadata() {
        let pass = ProxyDevirtualizationPass::new();
        assert_eq!(pass.name(), "proxy-devirtualization");
    }

    #[test]
    fn test_detect_proxy_void() {
        // Proxy: void method that forwards to Console.WriteLine(string)
        let target_token = Token::new(0x0A000001);

        let proxy_ssa = SsaFunctionBuilder::new(1, 0)
            .build_with(|f| {
                let param0 = f.arg(0, SsaType::I32);
                f.block(0, |b| {
                    b.call_void(MethodRef::new(target_token), &[param0]);
                    b.ret();
                });
            })
            .unwrap();

        let result = ProxyDevirtualizationPass::detect_proxy_pattern(&proxy_ssa);
        assert!(result.is_some(), "Should detect void proxy");

        let (target, arg_sources, kind) = result.unwrap();
        assert_eq!(target.token(), target_token);
        assert_eq!(arg_sources, vec![ProxyArgSource::Parameter(0)]);
        assert_eq!(kind, ForwardKind::Call);
    }

    #[test]
    fn test_detect_proxy_with_return() {
        let target_token = Token::new(0x0A000002);

        let proxy_ssa = SsaFunctionBuilder::new(2, 0)
            .build_with(|f| {
                let param0 = f.arg(0, SsaType::I32);
                let param1 = f.arg(1, SsaType::I32);
                f.block(0, |b| {
                    let result = b.call(
                        MethodRef::new(target_token),
                        &[param0, param1],
                        SsaType::I32,
                    );
                    b.ret_val(result);
                });
            })
            .unwrap();

        let result = ProxyDevirtualizationPass::detect_proxy_pattern(&proxy_ssa);
        assert!(result.is_some(), "Should detect proxy with return");

        let (target, arg_sources, kind) = result.unwrap();
        assert_eq!(target.token(), target_token);
        assert_eq!(
            arg_sources,
            vec![ProxyArgSource::Parameter(0), ProxyArgSource::Parameter(1)]
        );
        assert_eq!(kind, ForwardKind::Call);
    }

    #[test]
    fn test_detect_proxy_reordered_args() {
        let target_token = Token::new(0x0A000003);

        let proxy_ssa = SsaFunctionBuilder::new(2, 0)
            .build_with(|f| {
                let param0 = f.arg(0, SsaType::I32);
                let param1 = f.arg(1, SsaType::I32);
                f.block(0, |b| {
                    let result = b.call(
                        MethodRef::new(target_token),
                        &[param1, param0],
                        SsaType::I32,
                    );
                    b.ret_val(result);
                });
            })
            .unwrap();

        let result = ProxyDevirtualizationPass::detect_proxy_pattern(&proxy_ssa);
        assert!(result.is_some(), "Should detect proxy with reordered args");

        let (target, arg_sources, kind) = result.unwrap();
        assert_eq!(target.token(), target_token);
        assert_eq!(
            arg_sources,
            vec![ProxyArgSource::Parameter(1), ProxyArgSource::Parameter(0)]
        );
        assert_eq!(kind, ForwardKind::Call);
    }

    #[test]
    fn test_not_proxy_with_computation() {
        let target_token = Token::new(0x0A000004);

        let not_proxy_ssa = SsaFunctionBuilder::new(1, 0)
            .build_with(|f| {
                let param0 = f.arg(0, SsaType::I32);
                f.block(0, |b| {
                    let one = b.const_i32(1);
                    let sum = b.add(param0, one);
                    let result = b.call(MethodRef::new(target_token), &[sum], SsaType::I32);
                    b.ret_val(result);
                });
            })
            .unwrap();

        let result = ProxyDevirtualizationPass::detect_proxy_pattern(&not_proxy_ssa);
        assert!(
            result.is_none(),
            "Should NOT detect as proxy - has computation"
        );
    }

    #[test]
    fn test_devirtualize_proxy_via_run_on_method() {
        // Use high RIDs to avoid collisions with the test assembly's methods
        // (token 0x06000002 is a .ctor in crafted_2.exe, which the ctor check rejects)
        let proxy_token = Token::new(0x06000F02);
        let target_token = Token::new(0x0A000001);

        // Proxy: forwards arg0 to target
        let proxy_ssa = SsaFunctionBuilder::new(1, 0)
            .build_with(|f| {
                let param0 = f.arg(0, SsaType::I32);
                f.block(0, |b| {
                    b.call_void(MethodRef::new(target_token), &[param0]);
                    b.ret();
                });
            })
            .unwrap();

        // Caller: calls proxy
        let caller_token = Token::new(0x06000001);
        let mut caller_ssa = SsaFunctionBuilder::new(1, 0)
            .build_with(|f| {
                let arg0 = f.arg(0, SsaType::I32);
                f.block(0, |b| {
                    b.call_void(MethodRef::new(proxy_token), &[arg0]);
                    b.ret();
                });
            })
            .unwrap();

        let ctx = test_context();
        ctx.set_ssa(proxy_token, proxy_ssa);

        let pass = ProxyDevirtualizationPass::new();
        let assembly = test_assembly();
        let changed = pass
            .run_on_method(&mut caller_ssa, caller_token, &ctx, &assembly)
            .unwrap();

        assert!(changed, "Should have made changes");

        // Verify the call target was changed
        let block = caller_ssa.block(0).unwrap();
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

    #[test]
    fn test_noop_elimination() {
        let noop_token = Token::new(0x06000002);

        // No-op method: just returns
        let noop_ssa = SsaFunctionBuilder::new(0, 0)
            .build_with(|f| {
                f.block(0, |b| b.ret());
            })
            .unwrap();

        // Caller: calls the no-op
        let caller_token = Token::new(0x06000001);
        let mut caller_ssa = SsaFunctionBuilder::new(0, 0)
            .build_with(|f| {
                f.block(0, |b| {
                    b.call_void(MethodRef::new(noop_token), &[]);
                    b.ret();
                });
            })
            .unwrap();

        let ctx = test_context();
        ctx.set_ssa(noop_token, noop_ssa);

        let pass = ProxyDevirtualizationPass::new();
        let assembly = test_assembly();
        let changed = pass
            .run_on_method(&mut caller_ssa, caller_token, &ctx, &assembly)
            .unwrap();

        assert!(changed, "Should have made changes");

        // Verify the call was replaced with Nop
        let block = caller_ssa.block(0).unwrap();
        let first_instr = &block.instructions()[0];
        assert!(
            matches!(first_instr.op(), SsaOp::Nop),
            "Expected Nop, got {:?}",
            first_instr.op()
        );
    }

    #[test]
    fn test_constant_fold() {
        let const_token = Token::new(0x06000002);

        // Constant method: returns 42
        let const_ssa = SsaFunctionBuilder::new(0, 0)
            .build_with(|f| {
                f.block(0, |b| {
                    let v0 = b.const_i32(42);
                    b.ret_val(v0);
                });
            })
            .unwrap();

        // Caller: calls the constant method
        let caller_token = Token::new(0x06000001);
        let mut caller_ssa = SsaFunctionBuilder::new(0, 0)
            .build_with(|f| {
                f.block(0, |b| {
                    let result = b.call(MethodRef::new(const_token), &[], SsaType::I32);
                    b.ret_val(result);
                });
            })
            .unwrap();

        let ctx = test_context();
        ctx.set_ssa(const_token, const_ssa);

        let pass = ProxyDevirtualizationPass::new();
        let assembly = test_assembly();
        let changed = pass
            .run_on_method(&mut caller_ssa, caller_token, &ctx, &assembly)
            .unwrap();

        assert!(changed, "Should have made changes");

        // Verify the call was replaced with a constant
        let block = caller_ssa.block(0).unwrap();
        let first_instr = &block.instructions()[0];
        match first_instr.op() {
            SsaOp::Const { value, .. } => {
                assert_eq!(*value, ConstValue::I32(42));
            }
            other => panic!("Expected Const, got {:?}", other),
        }
    }

    #[test]
    fn test_no_self_recursion() {
        let self_token = Token::new(0x06000001);

        // Method that calls itself - should not devirtualize
        let self_ssa = SsaFunctionBuilder::new(1, 0)
            .build_with(|f| {
                let param0 = f.arg(0, SsaType::I32);
                f.block(0, |b| {
                    b.call_void(MethodRef::new(self_token), &[param0]);
                    b.ret();
                });
            })
            .unwrap();

        let mut caller_ssa = self_ssa.clone();

        let ctx = test_context();
        ctx.set_ssa(self_token, self_ssa);

        let pass = ProxyDevirtualizationPass::new();
        let assembly = test_assembly();
        let changed = pass
            .run_on_method(&mut caller_ssa, self_token, &ctx, &assembly)
            .unwrap();

        assert!(!changed, "Should not devirtualize self-recursive calls");
    }
}
