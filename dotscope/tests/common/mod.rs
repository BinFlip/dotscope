pub mod compatibility;
#[cfg(feature = "deobfuscation")]
pub mod framework;
pub mod verification;

use dotscope::{
    analysis::{ControlFlowGraph, SsaConverter, SsaFunction, SsaType, TypeProvider},
    assembly::{decode_blocks, InstructionAssembler},
    metadata::{signatures::SignatureLocalVariable, token::Token},
    CilObject, Result,
};

/// Test-only type provider that declares explicit types for synthetic CIL.
///
/// Used by converter tests that build SSA from inline CIL without real
/// assembly metadata. The test author explicitly chooses this provider
/// to declare "all args and locals in this test are I32."
#[allow(dead_code)]
pub struct TestTypeProvider {
    num_args: usize,
    num_locals: usize,
}

impl TestTypeProvider {
    /// Creates a new test type provider with the given argument and local counts.
    #[must_use]
    #[allow(dead_code)]
    pub fn new(num_args: usize, num_locals: usize) -> Self {
        Self {
            num_args,
            num_locals,
        }
    }
}

impl TypeProvider for TestTypeProvider {
    fn arg_type(&self, idx: u16) -> SsaType {
        if (idx as usize) < self.num_args {
            SsaType::I32
        } else {
            SsaType::Unknown
        }
    }

    fn local_type(&self, idx: u16) -> SsaType {
        if (idx as usize) < self.num_locals {
            SsaType::I32
        } else {
            SsaType::Unknown
        }
    }

    fn call_return_type(&self, _: Token) -> SsaType {
        SsaType::I32
    }

    fn newobj_type(&self, _: Token) -> SsaType {
        SsaType::Object
    }

    fn field_type(&self, _: Token) -> SsaType {
        SsaType::I32
    }

    fn call_indirect_return_type(&self, _: Token) -> SsaType {
        SsaType::I32
    }

    fn assembly(&self) -> Option<&CilObject> {
        None
    }

    fn local_type_signatures(&self) -> Option<Vec<SignatureLocalVariable>> {
        None
    }
}

/// Build a control flow graph (and raw bytecode) from assembled CIL.
///
/// Returns both the bytecode vector and the CFG so callers that need
/// the original bytes for round-trip verification can keep them.
#[allow(dead_code)]
pub fn build_cfg(assembler: InstructionAssembler) -> Result<(Vec<u8>, ControlFlowGraph<'static>)> {
    let (bytecode, _max_stack, _) = assembler.finish()?;
    let blocks = decode_blocks(&bytecode, 0, 0x1000, Some(bytecode.len()))?;
    let cfg = ControlFlowGraph::from_basic_blocks(blocks)?;
    Ok((bytecode, cfg))
}

/// Build SSA form from a control flow graph.
#[allow(dead_code)]
pub fn build_ssa(
    cfg: &ControlFlowGraph<'_>,
    num_args: usize,
    num_locals: usize,
) -> Result<SsaFunction> {
    SsaConverter::build(
        cfg,
        num_args,
        num_locals,
        &TestTypeProvider::new(num_args, num_locals),
    )
}
