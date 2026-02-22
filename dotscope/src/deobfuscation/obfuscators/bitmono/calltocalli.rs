//! BitMono CallToCalli reversal — SSA pass.
//!
//! Reverses BitMono's CallToCalli protection, which replaces direct `call`
//! instructions with an indirect `calli` sequence. The original method token is
//! embedded as an `ldc.i4` immediate, making this fully statically reversible.
//!
//! # Pattern (CIL)
//!
//! Each `call <MethodDef>` is replaced with a 10-instruction sequence:
//! ```text
//! ldtoken    <Module>                                 // → SSA: LoadToken
//! call       Type::GetTypeFromHandle                  // → SSA: Call
//! callvirt   Type::get_Module                         // → SSA: CallVirt
//! ldc.i4     0x06XXXXXX                               // → SSA: Const(I32)  ← target token
//! call       Module::ResolveMethod                    // → SSA: Call
//! callvirt   MethodBase::get_MethodHandle             // → SSA: CallVirt
//! stloc      <handle_local>                           // → SSA: StoreLocal
//! ldloca     <handle_local>                           // → SSA: LoadLocalAddr
//! call       RuntimeMethodHandle::GetFunctionPointer  // → SSA: Call
//! calli      <StandAloneSig>                          // → SSA: CallIndirect
//! ```
//!
//! # SSA Reversal
//!
//! The pass scans each block for `CallIndirect` instructions, then walks backward
//! within the same block looking for `LoadToken` + `Const(method_token)` +
//! `ResolveMethod` — the signature of a CallToCalli site. It replaces the
//! `CallIndirect` with a direct `Call` to the embedded token and NOPs out the
//! intermediate instructions. Subsequent DCE cleans up the NOPs.

use std::sync::Arc;

use crate::{
    analysis::{MethodRef, SsaFunction, SsaOp, SsaVarId},
    compiler::{CompilerContext, EventKind, ModificationScope, SsaPass},
    metadata::token::Token,
    CilObject, Result,
};

/// A detected CallToCalli site, potentially spanning multiple SSA blocks.
///
/// Each entry records the `CallIndirect` location, the resolved target token,
/// and all intermediate trampoline instructions that should be NOP'd out.
struct CalliSite {
    /// Block index of the `CallIndirect` instruction.
    callindirect_block: usize,
    /// Instruction index of the `CallIndirect` within its block.
    callindirect_idx: usize,
    /// The original method token extracted from the `Const` instruction.
    target_token: u32,
    /// The destination variable of the `CallIndirect` (if any).
    dest: Option<SsaVarId>,
    /// The arguments passed to the indirect call (excluding the function pointer).
    args: Vec<SsaVarId>,
    /// All intermediate trampoline instructions `(block_idx, instr_idx)` to NOP out.
    intermediates: Vec<(usize, usize)>,
}

/// SSA pass that reverses BitMono CallToCalli protection.
///
/// Replaces `CallIndirect` (from `calli`) with direct `Call` instructions using
/// the original method token embedded in the obfuscation pattern.
pub struct CalltocalliReversalPass;

impl SsaPass for CalltocalliReversalPass {
    fn name(&self) -> &'static str {
        "BitMonoCallToCalli"
    }

    fn description(&self) -> &'static str {
        "Reverses BitMono CallToCalli indirect call obfuscation"
    }

    fn modification_scope(&self) -> ModificationScope {
        ModificationScope::InstructionsOnly
    }

    fn run_on_method(
        &self,
        ssa: &mut SsaFunction,
        method_token: Token,
        ctx: &CompilerContext,
        assembly: &Arc<CilObject>,
    ) -> Result<bool> {
        let sites = find_sites(ssa, assembly);
        if sites.is_empty() {
            return Ok(false);
        }

        for site in &sites {
            let target_method = MethodRef::new(Token::new(site.target_token));

            // Replace CallIndirect with direct Call
            if let Some(block) = ssa.block_mut(site.callindirect_block) {
                if let Some(instr) = block.instruction_mut(site.callindirect_idx) {
                    let stored_type = instr.result_type().cloned();
                    instr.set_op(SsaOp::Call {
                        dest: site.dest,
                        method: target_method,
                        args: site.args.clone(),
                    });
                    instr.set_result_type(stored_type);
                }
            }

            // NOP out intermediate trampoline instructions and record
            // their metadata tokens as neutralized for cleanup
            for &(blk, idx) in &site.intermediates {
                if let Some(block) = ssa.block_mut(blk) {
                    if let Some(instr) = block.instruction(idx) {
                        match instr.op() {
                            SsaOp::Call { method, .. } | SsaOp::CallVirt { method, .. } => {
                                ctx.neutralized_tokens.insert(method.token());
                            }
                            _ => {}
                        }
                    }
                    if let Some(instr) = block.instruction_mut(idx) {
                        instr.set_op(SsaOp::Nop);
                    }
                }
            }
        }

        let count = sites.len();
        ctx.events
            .record(EventKind::InstructionRemoved)
            .method(method_token)
            .message(format!("Reversed {count} BitMono CallToCalli sites"));

        Ok(true)
    }
}

/// Finds all CallToCalli sites by tracing SSA def-use chains.
///
/// For each `CallIndirect`, follows the function pointer's definition chain
/// to identify the CallToCalli trampoline pattern:
///
/// ```text
/// fptr ← Call GetFunctionPointer(handle_addr)
///   handle_addr ← StoreLocal/LoadLocalAddr of get_MethodHandle result
///     ↳ CallVirt get_MethodHandle(resolved)
///       ↳ Call ResolveMethod(module, token_const)
///         ↳ token_const = Const(0x06XXXXXX)  ← target method token
///         ↳ module ← CallVirt get_Module(type_handle)
///           ↳ type_handle ← Call GetTypeFromHandle(tok)
///             ↳ tok ← LoadToken
/// ```
fn find_sites(ssa: &SsaFunction, assembly: &CilObject) -> Vec<CalliSite> {
    let mut sites = Vec::new();

    for (block_idx, block) in ssa.blocks().iter().enumerate() {
        for (i, instr) in block.instructions().iter().enumerate() {
            let SsaOp::CallIndirect {
                dest, fptr, args, ..
            } = instr.op()
            else {
                continue;
            };

            if let Some(site) =
                trace_calltocalli_chain(ssa, assembly, block_idx, i, *dest, *fptr, args)
            {
                sites.push(site);
            }
        }
    }

    sites
}

/// Traces the CallToCalli trampoline chain from a `CallIndirect`'s function
/// pointer variable back through the SSA def-use chain.
fn trace_calltocalli_chain(
    ssa: &SsaFunction,
    assembly: &CilObject,
    ci_block: usize,
    ci_idx: usize,
    dest: Option<SsaVarId>,
    fptr: SsaVarId,
    args: &[SsaVarId],
) -> Option<CalliSite> {
    let mut intermediates: Vec<(usize, usize)> = Vec::new();

    // Step 1: fptr should be defined by Call GetFunctionPointer(handle_addr)
    let fptr_def = ssa.get_definition(fptr)?;
    let (getfp_method, getfp_arg) = match fptr_def {
        SsaOp::Call { method, args, .. } if !args.is_empty() => (method.token(), args[0]),
        _ => return None,
    };
    if !is_method_named(assembly, getfp_method, "GetFunctionPointer") {
        return None;
    }
    intermediates.extend(def_site(ssa, fptr));

    // Step 2: The argument to GetFunctionPointer may be:
    // (a) Directly from CallVirt get_MethodHandle (SSA optimized away the local)
    // (b) A LoadLocalAddr (obfuscator uses stloc.X + ldloca.Y with mismatched
    //     local indices, breaking the def-use chain)
    //
    // For case (b), we fall back to scanning ALL instructions for the unique
    // CallVirt get_MethodHandle, since the def-use chain is intentionally broken.
    let resolved_var = match ssa.get_definition(getfp_arg)? {
        // Case (a): direct def-use
        SsaOp::CallVirt { method, args, .. }
            if !args.is_empty()
                && is_method_named(assembly, method.token(), "get_MethodHandle") =>
        {
            intermediates.extend(def_site(ssa, getfp_arg));
            args[0]
        }
        // Case (b): LoadLocalAddr — search globally for get_MethodHandle
        SsaOp::LoadLocalAddr { .. } => {
            intermediates.extend(def_site(ssa, getfp_arg));
            find_get_method_handle(ssa, assembly, &mut intermediates)?
        }
        _ => return None,
    };

    // Step 4: resolved should be from Call ResolveMethod(module, token_const)
    let rm_def = ssa.get_definition(resolved_var)?;
    let (module_var, token_const_var) = match rm_def {
        SsaOp::Call {
            method,
            args: rm_args,
            ..
        } if rm_args.len() >= 2 => {
            if !is_method_named(assembly, method.token(), "ResolveMethod") {
                return None;
            }
            intermediates.extend(def_site(ssa, resolved_var));
            (rm_args[0], rm_args[1])
        }
        _ => return None,
    };

    // Step 5: Extract the target method token from the Const
    let target_token = extract_method_token_from_const(ssa, token_const_var)?;

    // Step 6: Trace module ← CallVirt get_Module(type_handle)
    let gm_def = ssa.get_definition(module_var)?;
    let type_handle_var = match gm_def {
        SsaOp::CallVirt { args, .. } if !args.is_empty() => {
            intermediates.extend(def_site(ssa, module_var));
            args[0]
        }
        _ => return None,
    };

    // Step 7: type_handle ← Call GetTypeFromHandle(token_var)
    let gtfh_def = ssa.get_definition(type_handle_var)?;
    let loadtoken_arg = match gtfh_def {
        SsaOp::Call { args, .. } if !args.is_empty() => {
            intermediates.extend(def_site(ssa, type_handle_var));
            args[0]
        }
        _ => return None,
    };

    // Step 8: LoadToken at the start of the chain
    if matches!(ssa.get_definition(loadtoken_arg)?, SsaOp::LoadToken { .. }) {
        intermediates.extend(def_site(ssa, loadtoken_arg));
    }

    Some(CalliSite {
        callindirect_block: ci_block,
        callindirect_idx: ci_idx,
        target_token,
        dest,
        args: args.to_vec(),
        intermediates,
    })
}

/// Gets the (block, instruction) location of a variable's definition.
fn def_site(ssa: &SsaFunction, var: SsaVarId) -> Option<(usize, usize)> {
    let variable = ssa.variable(var)?;
    let ds = variable.def_site();
    Some((ds.block, ds.instruction?))
}

/// Searches all SSA blocks for a `CallVirt get_MethodHandle(resolved)` and
/// returns `resolved` (the first argument).
///
/// The obfuscator intentionally uses mismatched local indices (`stloc.X` followed
/// by `ldloca.Y` where X != Y), breaking the SSA def-use chain. This function
/// bypasses that by searching globally for the unique `get_MethodHandle` call
/// in the trampoline pattern.
fn find_get_method_handle(
    ssa: &SsaFunction,
    assembly: &CilObject,
    intermediates: &mut Vec<(usize, usize)>,
) -> Option<SsaVarId> {
    for (block_idx, block) in ssa.blocks().iter().enumerate() {
        for (instr_idx, instr) in block.instructions().iter().enumerate() {
            if let SsaOp::CallVirt { method, args, .. } = instr.op() {
                if !args.is_empty() && is_method_named(assembly, method.token(), "get_MethodHandle")
                {
                    intermediates.push((block_idx, instr_idx));
                    return Some(args[0]);
                }
            }
        }
    }
    None
}

/// Checks if a metadata token resolves to a method with the given name substring.
fn is_method_named(assembly: &CilObject, token: Token, name: &str) -> bool {
    resolve_method_name(assembly, token).is_some_and(|n| n.contains(name))
}

/// Extracts a method token value from a Const definition of an SSA variable.
///
/// Returns `Some(token_value)` if the variable is defined by a `Const` whose
/// value is a valid method token (MethodDef 0x06, MemberRef 0x0A, MethodSpec 0x2B).
fn extract_method_token_from_const(ssa: &SsaFunction, var: SsaVarId) -> Option<u32> {
    let def = ssa.get_definition(var)?;
    let SsaOp::Const { value, .. } = def else {
        return None;
    };

    let raw = value.as_i32()? as u32;
    let table = raw >> 24;
    if table == 0x06 || table == 0x0A || table == 0x2B {
        Some(raw)
    } else {
        None
    }
}

/// Resolves a metadata token to a qualified member name (e.g. `"Module.ResolveMethod"`).
fn resolve_method_name(assembly: &CilObject, token: Token) -> Option<String> {
    // Try MemberRef first (most common for BCL calls)
    if let Some(member) = assembly.member_ref(&token) {
        if let Some(type_name) = member.declaredby.fullname() {
            return Some(format!("{}::{}", type_name, member.name));
        }
        return Some(member.name.clone());
    }

    // Try MethodDef
    if let Some(method) = assembly.method(&token) {
        return Some(method.name.clone());
    }

    None
}

#[cfg(test)]
mod tests {
    use crate::metadata::token::Token;

    #[test]
    fn test_extract_method_token() {
        // Verify that a raw i32 value like 0x06000042 extracted from
        // get_i32_operand() correctly maps to a MethodDef token.
        let raw_i32: i32 = 0x0600_0042_u32 as i32;
        let token_val = raw_i32 as u32;

        assert_eq!(token_val >> 24, 0x06, "Should be a MethodDef table token");
        assert_eq!(token_val & 0x00FF_FFFF, 0x42, "Row should be 0x42");

        let token = Token::new(token_val);
        assert_eq!(token.table(), 0x06);
        assert_eq!(token.row(), 0x42);
    }

    #[test]
    fn test_non_method_token_rejected() {
        // A TypeRef token (0x01) should not be treated as a valid call target
        let raw_i32: i32 = 0x0100_0010_u32 as i32;
        let token_val = raw_i32 as u32;
        let table = token_val >> 24;
        assert!(
            table != 0x06 && table != 0x0A && table != 0x2B,
            "TypeRef should not match any valid method token table"
        );
    }

    #[test]
    fn test_memberref_token_accepted() {
        let raw_i32: i32 = 0x0A00_0005_u32 as i32;
        let token_val = raw_i32 as u32;
        let table = token_val >> 24;
        assert_eq!(table, 0x0A, "Should be a MemberRef table token");
    }

    #[test]
    fn test_methodspec_token_accepted() {
        let raw_i32: i32 = 0x2B00_0003_u32 as i32;
        let token_val = raw_i32 as u32;
        let table = token_val >> 24;
        assert_eq!(table, 0x2B, "Should be a MethodSpec table token");
    }
}
