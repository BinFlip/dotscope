//! JIEJIE.NET typeof() restoration pass.
//!

//! Replaces `Call(GetTypeInstance, index)` operations with the original
//! `LoadToken` + `Call(GetTypeFromHandle)` pattern that JIEJIE.NET replaced
//! with its RuntimeTypeHandleContainer indirection.
//!
//! # Pipeline Position
//!
//! This pass runs in the **Value** phase, after Int32ValueContainer resolution
//! (which resolves the index constants) and before CFF unflattening.
//!
//! # Algorithm
//!
//! 1. During technique initialization, parse the container's `.cctor` to extract
//!    the ordered list of `ldtoken` type tokens (index 0, 1, 2, ...)
//! 2. For each method, scan for `Call { method: accessor_token, args: [index_var] }`
//! 3. Resolve `index_var` to a `Const(I32(N))` via the SSA constant map
//! 4. Replace the Call with `LoadToken` + `Call(GetTypeFromHandle)` to produce
//!    a `System.Type` object (not just a `RuntimeTypeHandle`)
//!
//! # Example
//!
//! ```text
//! // Before:
//! v1 = Const(I32(2))
//! v2 = call GetTypeInstance(v1)   // returns System.Type
//!
//! // After:
//! v1 = Const(I32(2))
//! vN = ldtoken TypeRef(0x01000005)           // RuntimeTypeHandle
//! v2 = call GetTypeFromHandle(vN)            // System.Type
//! ```

use log::debug;

use crate::{
    analysis::{
        ConstValue, DefSite, MethodRef, SsaFunction, SsaInstruction, SsaOp, SsaType, SsaVarId,
        TypeRef, VariableOrigin,
    },
    compiler::{CompilerContext, EventKind, ModificationScope, SsaPass},
    metadata::token::Token,
    CilObject, Result,
};

/// SSA pass that replaces JIEJIE.NET typeof container calls with
/// `LoadToken` + `Call(GetTypeFromHandle)`.
///
/// Created by the `jiejienet.typeof` technique after detection identifies the
/// container class and its `.cctor` is parsed for the type token mapping.
pub struct TypeOfRestorationPass {
    /// Token of the GetTypeInstance accessor method.
    accessor_token: Token,
    /// Ordered type tokens extracted from the container's .cctor.
    /// Index in the vector corresponds to the integer argument passed to the accessor.
    type_tokens: Vec<Token>,
    /// MemberRef token for `System.Type::GetTypeFromHandle(RuntimeTypeHandle)`.
    get_type_from_handle_token: Token,
}

impl TypeOfRestorationPass {
    /// Creates a new typeof restoration pass.
    ///
    /// # Arguments
    ///
    /// * `accessor_token` - Token of the container's GetTypeInstance method
    /// * `type_tokens` - Ordered type tokens from the container's .cctor ldtoken instructions
    /// * `get_type_from_handle_token` - MemberRef token for `Type.GetTypeFromHandle`
    #[must_use]
    pub fn new(
        accessor_token: Token,
        type_tokens: Vec<Token>,
        get_type_from_handle_token: Token,
    ) -> Self {
        Self {
            accessor_token,
            type_tokens,
            get_type_from_handle_token,
        }
    }
}

impl SsaPass for TypeOfRestorationPass {
    fn name(&self) -> &'static str {
        "jiejie-typeof-restore"
    }

    fn description(&self) -> &'static str {
        "Replaces JIEJIE.NET typeof container calls with ldtoken + GetTypeFromHandle"
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
        if self.type_tokens.is_empty() {
            return Ok(false);
        }

        // Build constant map to resolve index arguments
        let constants = ssa.find_constants();

        // Collect replacement info: (block_idx, instr_idx, type_token, original_dest)
        let mut replacements: Vec<(usize, usize, Token, SsaVarId)> = Vec::new();

        for (block_idx, block) in ssa.blocks().iter().enumerate() {
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                if let SsaOp::Call { dest, method, args } = instr.op() {
                    if method.token() != self.accessor_token {
                        continue;
                    }

                    // The accessor takes a single int32 argument (the index)
                    if args.len() != 1 {
                        continue;
                    }

                    // Resolve the index argument to a constant
                    let Some(ConstValue::I32(index)) = constants.get(&args[0]) else {
                        continue;
                    };

                    let index = *index as usize;
                    if index >= self.type_tokens.len() {
                        debug!(
                            "jiejie-typeof: index {} out of bounds (max {}), skipping",
                            index,
                            self.type_tokens.len()
                        );
                        continue;
                    }

                    if let Some(dest) = dest {
                        replacements.push((block_idx, instr_idx, self.type_tokens[index], *dest));
                    }
                }
            }
        }

        if replacements.is_empty() {
            return Ok(false);
        }

        // Apply replacements in reverse order within each block to maintain indices
        // when inserting new instructions.
        // Sort by (block_idx, instr_idx) descending so later indices are processed first.
        replacements.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.cmp(&a.1)));

        for (block_idx, instr_idx, type_token, orig_dest) in &replacements {
            // Create a temporary variable for the RuntimeTypeHandle (LoadToken result)
            let handle_var = ssa.create_variable(
                VariableOrigin::Phi, // synthetic origin
                0,
                DefSite::instruction(*block_idx, *instr_idx),
                SsaType::RuntimeTypeHandle,
            );

            // Replace the original Call with LoadToken into the temp variable
            ssa.replace_instruction_op(
                *block_idx,
                *instr_idx,
                SsaOp::LoadToken {
                    dest: handle_var,
                    token: TypeRef::new(*type_token),
                },
            );

            // Insert a Call(GetTypeFromHandle) instruction right after the LoadToken.
            // This converts RuntimeTypeHandle → System.Type, matching what GetTypeInstance did.
            let call_instr = SsaInstruction::synthetic(SsaOp::Call {
                dest: Some(*orig_dest),
                method: MethodRef::new(self.get_type_from_handle_token),
                args: vec![handle_var],
            });

            ssa.blocks_mut()[*block_idx]
                .instructions_mut()
                .insert(instr_idx + 1, call_instr);

            ctx.events.record(EventKind::ValueResolved);
        }

        Ok(true)
    }
}
