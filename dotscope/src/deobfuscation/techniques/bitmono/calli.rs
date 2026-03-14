//! BitMono CallToCalli detection and reversal.
//!
//! Detects and reverses BitMono's CallToCalli protection, which replaces direct
//! `call` instructions with an indirect `calli` sequence. The obfuscation
//! embeds the original method token as an `ldc.i4` immediate, making it fully
//! statically reversible.
//!
//! # CIL Pattern
//!
//! Each `call <MethodDef>` is replaced with a 10-instruction sequence:
//! ```text
//! ldtoken    <Module>                                 // -> SSA: LoadToken
//! call       Type::GetTypeFromHandle                  // -> SSA: Call
//! callvirt   Type::get_Module                         // -> SSA: CallVirt
//! ldc.i4     0x06XXXXXX                               // -> SSA: Const(I32) <- target token
//! call       Module::ResolveMethod                    // -> SSA: Call
//! callvirt   MethodBase::get_MethodHandle             // -> SSA: CallVirt
//! stloc      <handle_local>                           // -> SSA: StoreLocal
//! ldloca     <handle_local>                           // -> SSA: LoadLocalAddr
//! call       RuntimeMethodHandle::GetFunctionPointer  // -> SSA: Call
//! calli      <StandAloneSig>                          // -> SSA: CallIndirect
//! ```
//!
//! # Detection
//!
//! Scans all methods for `calli` instructions preceded by the characteristic
//! `ldtoken <Module>` + `ResolveMethod` + `GetFunctionPointer` trampoline
//! pattern. Methods containing at least one such site are recorded in
//! [`CalliFindings`] so that the SSA pass processes only affected methods.
//!
//! # SSA Pass
//!
//! [`CalltocalliReversalPass`] runs on detected methods and traces SSA def-use
//! chains from each `CallIndirect` back through the trampoline looking for
//! `LoadToken` + `Const(method_token)` + `ResolveMethod`. Each `CallIndirect`
//! is replaced with a direct `Call` to the embedded token, and intermediate
//! trampoline instructions are NOP'd out. Subsequent DCE cleans up the NOPs.

use std::{any::Any, collections::HashSet, sync::Arc};

use crate::{
    analysis::{MethodRef, SsaFunction, SsaOp, SsaVarId},
    compiler::{CompilerContext, EventKind, ModificationScope, SsaPass},
    deobfuscation::{
        context::AnalysisContext,
        techniques::{Detection, Evidence, PassPhase, Technique, TechniqueCategory},
        utils::is_method_named,
    },
    metadata::token::Token,
    CilObject, Result,
};

/// Findings from BitMono CallToCalli detection.
#[derive(Debug)]
pub struct CalliFindings {
    /// Method tokens containing CallToCalli conversion sites.
    pub method_tokens: HashSet<Token>,
    /// Total number of CallToCalli sites across all affected methods.
    pub site_count: usize,
}

/// Detects BitMono's CallToCalli indirect call protection.
///
/// Identifies methods containing `calli` instructions preceded by the
/// `ldtoken <Module>` + `ResolveMethod` + `GetFunctionPointer` trampoline
/// pattern. Detected method tokens are passed to [`CalltocalliReversalPass`]
/// so it only processes affected methods, and the SSA-level def-use chain
/// tracing performs the precise reversal.
pub struct BitMonoCalli;

impl Technique for BitMonoCalli {
    fn id(&self) -> &'static str {
        "bitmono.calli"
    }

    fn name(&self) -> &'static str {
        "BitMono CallToCalli Reversal"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Structure
    }

    fn detect(&self, assembly: &CilObject) -> Detection {
        let mut method_tokens = HashSet::new();
        let mut site_count = 0usize;

        for method_entry in assembly.methods() {
            let method = method_entry.value();
            let instructions: Vec<_> = method.instructions().collect();

            let mut method_sites = 0usize;
            let mut i = 0;
            while i < instructions.len() {
                if instructions[i].mnemonic == "calli" {
                    // Walk backwards up to 12 instructions looking for the
                    // characteristic BitMono trampoline pattern:
                    //   ldtoken <Module> → GetTypeFromHandle → get_Module
                    //   → ldc.i4 <token> → ResolveMethod → get_MethodHandle
                    //   → GetFunctionPointer → calli
                    let window_start = i.saturating_sub(12);
                    let window = &instructions[window_start..i];

                    let has_ldtoken = window.iter().any(|instr| instr.mnemonic == "ldtoken");
                    let has_trampoline_api = window.iter().any(|instr| {
                        instr
                            .get_token_operand()
                            .and_then(|t| assembly.resolve_method_name(t))
                            .is_some_and(|n| {
                                n.contains("ResolveMethod") || n.contains("GetFunctionPointer")
                            })
                    });

                    if has_ldtoken && has_trampoline_api {
                        method_sites += 1;
                    }
                }
                i += 1;
            }

            if method_sites > 0 {
                method_tokens.insert(method.token);
                site_count += method_sites;
            }
        }

        if site_count == 0 {
            return Detection::new_empty();
        }

        let method_count = method_tokens.len();
        Detection::new_detected(
            vec![Evidence::BytecodePattern(format!(
                "{site_count} CallToCalli conversion sites in {method_count} methods \
                 (ldtoken + ResolveMethod + calli)"
            ))],
            Some(Box::new(CalliFindings {
                method_tokens,
                site_count,
            }) as Box<dyn Any + Send + Sync>),
        )
    }

    fn ssa_phase(&self) -> Option<PassPhase> {
        Some(PassPhase::Simplify)
    }

    fn create_pass(
        &self,
        _ctx: &AnalysisContext,
        detection: &Detection,
        _assembly: &Arc<CilObject>,
    ) -> Option<Box<dyn SsaPass>> {
        let findings = detection.findings::<CalliFindings>()?;
        // Use confirmed method tokens from detection (may be empty if only IL-detected,
        // in which case the pass runs on all methods as a safe fallback).
        Some(Box::new(CalltocalliReversalPass::with_methods(
            findings.method_tokens.iter().copied(),
        )))
    }

    fn detect_ssa(&self, ctx: &AnalysisContext, assembly: &CilObject) -> Detection {
        let mut method_tokens = HashSet::new();
        let mut site_count = 0usize;
        for entry in ctx.ssa_functions.iter() {
            let sites = find_calli_sites(entry.value(), assembly);
            if !sites.is_empty() {
                site_count += sites.len();
                method_tokens.insert(*entry.key());
            }
        }
        if site_count == 0 {
            return Detection::new_empty();
        }
        let method_count = method_tokens.len();
        Detection::new_detected(
            vec![Evidence::BytecodePattern(format!(
                "{site_count} CallToCalli sites in {method_count} methods \
                 (SSA def-use chain confirmed)"
            ))],
            Some(Box::new(CalliFindings {
                method_tokens,
                site_count,
            }) as Box<dyn Any + Send + Sync>),
        )
    }
}

/// A detected CallToCalli site with the resolved target and intermediate instructions.
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
/// Only runs on methods identified during detection (via [`CalliFindings::method_tokens`]).
/// For each method, traces SSA def-use chains from every `CallIndirect` back through
/// the trampoline to extract the embedded method token, replaces the `CallIndirect`
/// with a direct `Call`, and NOPs intermediate trampoline instructions.
struct CalltocalliReversalPass {
    /// Methods identified during detection as containing CallToCalli sites.
    target_methods: HashSet<Token>,
}

impl CalltocalliReversalPass {
    /// Creates a pass targeting specific methods identified during detection.
    ///
    /// # Arguments
    ///
    /// * `tokens` - Iterator of method [`Token`]s that contain CallToCalli sites.
    ///   Pass an empty iterator to run on all methods (used when the IL-level window
    ///   detection may have missed cross-block trampoline setups).
    ///
    /// # Returns
    ///
    /// A [`CalltocalliReversalPass`] configured with the provided target set.
    fn with_methods(tokens: impl IntoIterator<Item = Token>) -> Self {
        Self {
            target_methods: tokens.into_iter().collect(),
        }
    }
}

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

    fn should_run(&self, method_token: Token, _ctx: &CompilerContext) -> bool {
        self.target_methods.is_empty() || self.target_methods.contains(&method_token)
    }

    fn run_on_method(
        &self,
        ssa: &mut SsaFunction,
        method_token: Token,
        ctx: &CompilerContext,
        assembly: &CilObject,
    ) -> Result<bool> {
        let sites = find_calli_sites(ssa, assembly);
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

            // NOP out intermediate trampoline instructions
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

/// Finds all CallToCalli sites by tracing SSA def-use chains from `CallIndirect`.
///
/// Iterates every `CallIndirect` instruction in every block and attempts to
/// trace its function-pointer argument back through the BitMono trampoline
/// chain. Sites where the full chain is confirmed are returned for patching.
///
/// # Arguments
///
/// * `ssa` - The SSA function graph to scan.
/// * `assembly` - The assembly, used for resolving method names during tracing.
///
/// # Returns
///
/// A [`Vec`] of [`CalliSite`]s, one per confirmed `CallIndirect` that matches
/// the BitMono trampoline pattern. Empty if no sites are found.
fn find_calli_sites(ssa: &SsaFunction, assembly: &CilObject) -> Vec<CalliSite> {
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

/// Resolves the source of a `calli` function pointer back to a
/// `Call GetFunctionPointer` instruction, handling the case where the
/// function pointer is stored to a local and loaded back across a
/// basic-block boundary (causing SSA to create a PHI node).
///
/// # Arguments
///
/// * `ssa` - The SSA function graph.
/// * `assembly` - The assembly, used for resolving method names.
/// * `fptr` - The SSA variable holding the function pointer at the `CallIndirect`.
///
/// # Returns
///
/// `Some((def_var, method_token, arg_var))` where `def_var` is the SSA variable
/// directly defined by `Call GetFunctionPointer`, `method_token` is its token,
/// and `arg_var` is its first argument (the method handle address). Returns
/// `None` if no matching `GetFunctionPointer` call can be found.
fn resolve_fptr_source(
    ssa: &SsaFunction,
    assembly: &CilObject,
    fptr: SsaVarId,
) -> Option<(SsaVarId, Token, SsaVarId)> {
    // Fast path: fptr is directly defined by Call GetFunctionPointer.
    if let Some(def) = ssa.get_definition(fptr) {
        if let SsaOp::Call { method, args, .. } = def {
            if !args.is_empty() && is_method_named(assembly, method.token(), "GetFunctionPointer") {
                return Some((fptr, method.token(), args[0]));
            }
        }
        // Defined by something else — not a calli trampoline.
        return None;
    }

    // Slow path: fptr is defined by a PHI node (e.g., junk br.s creates an extra
    // block, so the GetFunctionPointer result is stored through a local and the
    // SSA variable at the join point is a PHI). Follow each operand one level.
    let (_block_idx, phi) = ssa.find_phi_defining(fptr)?;
    for operand in phi.operands() {
        let op_var = operand.value();
        if let Some(SsaOp::Call { method, args, .. }) = ssa.get_definition(op_var) {
            if !args.is_empty() && is_method_named(assembly, method.token(), "GetFunctionPointer") {
                return Some((op_var, method.token(), args[0]));
            }
        }
    }

    None
}

/// Traces the CallToCalli trampoline chain from a `CallIndirect`'s function
/// pointer variable back through the SSA def-use chain.
///
/// The expected chain is:
/// ```text
/// LoadToken <Module>
///   → Call GetTypeFromHandle(token)
///   → CallVirt get_Module(type)
///   → Call ResolveMethod(module, Const(target_token))
///   → CallVirt get_MethodHandle(method_base)
///   → Call GetFunctionPointer(handle)
///   → CallIndirect(fptr, args...)
/// ```
///
/// # Arguments
///
/// * `ssa` - The SSA function graph containing the chain.
/// * `assembly` - The assembly, used for resolving API method names.
/// * `ci_block` - Block index of the `CallIndirect` instruction.
/// * `ci_idx` - Instruction index of the `CallIndirect` within its block.
/// * `dest` - Optional SSA variable that receives the indirect call's return value.
/// * `fptr` - SSA variable holding the function pointer passed to `CallIndirect`.
/// * `args` - Arguments passed to the indirect call (excluding the function pointer).
///
/// # Returns
///
/// `Some(CalliSite)` if the full trampoline chain is confirmed, or `None` if
/// the def-use chain does not match the expected BitMono pattern.
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

    // Step 1: fptr should be defined by Call GetFunctionPointer(handle_addr).
    // When the function pointer is stored to a local and loaded back across a
    // basic-block boundary (e.g., BitMono junk br.s creates an extra block),
    // the SSA will define fptr via a PHI node rather than directly from the
    // GetFunctionPointer call. Follow PHI operands one level deep to handle this.
    let (getfp_actual_def_var, _getfp_method, getfp_arg) =
        resolve_fptr_source(ssa, assembly, fptr)?;
    intermediates.extend(def_site(ssa, getfp_actual_def_var));

    // Step 2: Argument to GetFunctionPointer may be:
    // (a) Directly from CallVirt get_MethodHandle (SSA optimized away the local)
    // (b) A LoadLocalAddr (obfuscator uses stloc.X + ldloca.Y with mismatched
    //     indices, breaking the def-use chain)
    let resolved_var = match ssa.get_definition(getfp_arg)? {
        SsaOp::CallVirt { method, args, .. }
            if !args.is_empty()
                && is_method_named(assembly, method.token(), "get_MethodHandle") =>
        {
            intermediates.extend(def_site(ssa, getfp_arg));
            args[0]
        }
        SsaOp::LoadLocalAddr { .. } => {
            intermediates.extend(def_site(ssa, getfp_arg));
            find_get_method_handle(ssa, assembly, &mut intermediates)?
        }
        _ => return None,
    };

    // Step 3: resolved should be from Call ResolveMethod(module, token_const)
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

    // Step 4: Extract the target method token from the Const
    let target_token = extract_method_token_from_const(ssa, token_const_var)?;

    // Step 5: Trace module ← CallVirt get_Module(type_handle)
    let gm_def = ssa.get_definition(module_var)?;
    let type_handle_var = match gm_def {
        SsaOp::CallVirt { args, .. } if !args.is_empty() => {
            intermediates.extend(def_site(ssa, module_var));
            args[0]
        }
        _ => return None,
    };

    // Step 6: type_handle ← Call GetTypeFromHandle(token_var)
    let gtfh_def = ssa.get_definition(type_handle_var)?;
    let loadtoken_arg = match gtfh_def {
        SsaOp::Call { args, .. } if !args.is_empty() => {
            intermediates.extend(def_site(ssa, type_handle_var));
            args[0]
        }
        _ => return None,
    };

    // Step 7: LoadToken at the start of the chain
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

/// Gets the `(block_index, instruction_index)` location of a variable's definition.
///
/// # Arguments
///
/// * `ssa` - The SSA function graph.
/// * `var` - The SSA variable whose definition site is requested.
///
/// # Returns
///
/// `Some((block, instr))` if the variable has a known definition site with an
/// instruction index, or `None` if the variable is undefined or defined only
/// by a phi node (no instruction index).
fn def_site(ssa: &SsaFunction, var: SsaVarId) -> Option<(usize, usize)> {
    let variable = ssa.variable(var)?;
    let ds = variable.def_site();
    Some((ds.block, ds.instruction?))
}

/// Searches all SSA blocks for `CallVirt get_MethodHandle` and returns its
/// first argument.
///
/// Used as a fallback when the obfuscator emits mismatched `stloc`/`ldloca`
/// indices that break the normal def-use chain. In that case the standard
/// backwards traversal cannot follow the chain from the `LoadLocalAddr` to the
/// `CallVirt get_MethodHandle`, so this function performs a linear scan instead.
///
/// # Arguments
///
/// * `ssa` - The SSA function graph to scan.
/// * `assembly` - The assembly, used for resolving the `get_MethodHandle` name.
/// * `intermediates` - Accumulator for trampoline instruction locations;
///   the found instruction's `(block, instr)` index is appended if found.
///
/// # Returns
///
/// `Some(var)` containing the first argument to `get_MethodHandle` (the
/// `MethodBase` value), or `None` if no such call exists in the function.
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

/// Extracts a method token value from the `Const` definition of an SSA variable.
///
/// Validates that the constant is a metadata token for one of the three
/// method-referencing tables: MethodDef (`0x06`), MemberRef (`0x0A`), or
/// MethodSpec (`0x2B`).
///
/// # Arguments
///
/// * `ssa` - The SSA function graph containing the variable.
/// * `var` - The SSA variable whose definition should be a `Const`.
///
/// # Returns
///
/// `Some(raw_token)` if the variable is defined by a `Const` with an
/// integer value whose table byte is `0x06`, `0x0A`, or `0x2B`; `None`
/// otherwise.
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

#[cfg(test)]
mod tests {
    use crate::deobfuscation::techniques::{bitmono::BitMonoCalli, Technique};
    use crate::test::helpers::load_sample;

    #[test]
    fn test_detect_positive() {
        let assembly = load_sample("tests/samples/packers/bitmono/0.39.0/bitmono_calltocalli.exe");

        let technique = BitMonoCalli;
        let detection = technique.detect(&assembly);

        assert!(
            detection.detected,
            "BitMonoCalli should detect CallToCalli pattern in bitmono_calltocalli.exe"
        );
        assert!(
            !detection.evidence.is_empty(),
            "Detection should include evidence"
        );
    }

    #[test]
    fn test_detect_negative() {
        let assembly = load_sample("tests/samples/packers/confuserex/1.6.0/original.exe");

        let technique = BitMonoCalli;
        let detection = technique.detect(&assembly);

        assert!(
            !detection.detected,
            "BitMonoCalli should not detect CallToCalli in a non-BitMono assembly"
        );
    }
}
