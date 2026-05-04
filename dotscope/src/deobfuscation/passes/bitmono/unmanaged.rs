//! BitMono UnmanagedString reversal SSA pass.
//!
//! Replaces `call <fake_native>` + `newobj string::.ctor(ptr)` patterns with
//! `DecryptedString` constants, which the codegen pipeline emits as `ldstr`
//! instructions.
//!
//! # Pipeline Position
//!
//! This pass runs in the **Simplify** phase, after detection has extracted
//! embedded strings from native method bodies.
//!
//! # Algorithm
//!
//! 1. For each block, scan for `Call` instructions targeting a known fake native
//!    method token
//! 2. Look for a subsequent `NewObj` string constructor that consumes the call result
//! 3. Replace the `NewObj` with `Const(DecryptedString(...))` and NOP the `Call`
//!
//! # Example
//!
//! ```text
//! // Before:
//! v1 = Call { method: <fake_native_token>, args: [] }
//! v2 = NewObj { ctor: <string_ctor_token>, args: [v1] }
//!
//! // After:
//! Nop  (was Call)
//! v2 = Const(DecryptedString("Hello"))
//! ```

use std::collections::HashMap;

use crate::{
    analysis::{ConstValue, SsaFunction, SsaOp, SsaVarId},
    compiler::{CompilerContext, EventKind, ModificationScope, SsaPass},
    metadata::token::Token,
    CilObject, Result,
};

/// SSA pass that replaces UnmanagedString call+newobj patterns with string constants.
///
/// For each method, scans for the pattern:
/// ```text
/// v1 = Call { method: <fake_native_token>, args: [] }
/// v2 = NewObj { ctor: <string_ctor_token>, args: [v1] }
/// ```
/// and replaces with:
/// ```text
/// Nop  (was Call)
/// v2 = Const { value: DecryptedString("...") }  (was NewObj)
/// ```
///
/// The codegen pipeline handles `DecryptedString` constants by pre-interning them
/// to the #US heap and emitting proper `ldstr` instructions.
pub struct UnmanagedStringReversalPass {
    /// Maps fake native method tokens to their decrypted string values.
    pub(crate) native_string_map: HashMap<Token, String>,
}

impl SsaPass for UnmanagedStringReversalPass {
    fn name(&self) -> &'static str {
        "BitMonoUnmanagedString"
    }

    fn description(&self) -> &'static str {
        "Replaces calls to fake native string methods with ldstr constants"
    }

    fn modification_scope(&self) -> ModificationScope {
        ModificationScope::InstructionsOnly
    }

    fn run_on_method(
        &self,
        ssa: &mut SsaFunction,
        _method_token: Token,
        ctx: &CompilerContext,
        _assembly: &CilObject,
    ) -> Result<bool> {
        let mut changed = false;

        for block_idx in 0..ssa.blocks().len() {
            let sites = find_unmanaged_string_sites(ssa, block_idx, &self.native_string_map);
            if sites.is_empty() {
                continue;
            }

            // Apply in reverse order to keep indices valid
            let block = match ssa.block_mut(block_idx) {
                Some(b) => b,
                None => continue,
            };

            for site in sites.iter().rev() {
                // Replace NewObj with DecryptedString constant
                if let Some(instr) = block.instruction_mut(site.newobj_idx) {
                    instr.set_op(SsaOp::Const {
                        dest: site.newobj_dest,
                        value: ConstValue::DecryptedString(site.decrypted.clone()),
                    });
                }

                // NOP the Call instruction
                if let Some(instr) = block.instruction_mut(site.call_idx) {
                    instr.set_op(SsaOp::Nop);
                }

                changed = true;
            }

            if !sites.is_empty() {
                ctx.events
                    .record(EventKind::StringDecrypted)
                    .message(format!(
                        "BitMonoUnmanagedString: reversed {} call+newobj sites in block {}",
                        sites.len(),
                        block_idx,
                    ));
            }
        }

        Ok(changed)
    }
}

/// A detected call+newobj site for UnmanagedString reversal.
struct UnmanagedStringSite {
    /// Index of the `Call` instruction in the block.
    call_idx: usize,
    /// Index of the `NewObj` instruction in the block.
    newobj_idx: usize,
    /// SSA variable defined by the NewObj (destination of the string value).
    newobj_dest: SsaVarId,
    /// The decrypted string value.
    decrypted: String,
}

/// Finds `call <native>` + `newobj string::.ctor(ptr)` patterns in a block.
///
/// Scans a single SSA block for pairs where a `Call` targets a known fake native
/// method token and is immediately consumed by a `NewObj` string constructor.
/// Returns one [`UnmanagedStringSite`] per matched pair.
///
/// # Arguments
///
/// * `ssa` - The SSA function graph containing the block.
/// * `block_idx` - Index of the block to scan.
/// * `native_map` - Map from fake native method token to its decrypted string.
///
/// # Returns
///
/// A [`Vec`] of detected sites, in forward order within the block. Empty if
/// no matching patterns exist in the block.
fn find_unmanaged_string_sites(
    ssa: &SsaFunction,
    block_idx: usize,
    native_map: &HashMap<Token, String>,
) -> Vec<UnmanagedStringSite> {
    let mut sites = Vec::new();

    let Some(block) = ssa.block(block_idx) else {
        return sites;
    };

    let instructions = block.instructions();

    for (i, instr) in instructions.iter().enumerate() {
        // Look for Call to a fake native method
        let (call_dest, call_token) = match instr.op() {
            SsaOp::Call { dest, method, .. } => {
                let Some(d) = dest else { continue };
                (*d, method.token())
            }
            _ => continue,
        };

        // Check if this call targets a known fake native method
        let Some(decrypted) = native_map.get(&call_token) else {
            continue;
        };

        // Look for NewObj in subsequent instructions that uses the call result.
        // Only stop on a NewObj consuming call_dest — other uses (e.g., debug
        // traces) should not prevent finding the actual string constructor.
        // Limit search distance to avoid O(n²) behaviour across many call sites.
        const MAX_SEARCH_DISTANCE: usize = 20;
        let start = i.saturating_add(1);
        let search_end = start
            .saturating_add(MAX_SEARCH_DISTANCE)
            .min(instructions.len());
        let take = search_end.saturating_sub(start);
        for (j, next) in instructions.iter().enumerate().skip(start).take(take) {
            if let SsaOp::NewObj { dest, args, .. } = next.op() {
                if args.len() == 1 && args.first() == Some(&call_dest) {
                    sites.push(UnmanagedStringSite {
                        call_idx: i,
                        newobj_idx: j,
                        newobj_dest: *dest,
                        decrypted: decrypted.clone(),
                    });
                    break;
                }
            }
        }
    }

    sites
}
