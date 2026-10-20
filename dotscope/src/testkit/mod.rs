//! Test support shared by dotscope's unit and integration tests.
//!
//! Unit tests reach it as `crate::testkit`; integration tests as `dotscope::testkit`, through
//! the `testkit` feature the crate's own dev-dependency on itself turns on. Cargo unifies that
//! dev-dependency with the crate under test, so both see one crate instance and its types. It
//! is unstable and outside the semver surface.
//!
//! - [`builders`]: fluent builders for metadata objects (types, methods, references).
//! - [`factories`]: assemblies and rows crafted for validator and table tests.
//! - [`fixtures`]: the committed samples under `tests/samples`, resolved and checked against
//!   their manifest.
//! - [`helpers`]: sample loading and small utilities.
//! - [`framework`]: the obfuscator sample harness (deobfuscate, verify, summarize).
//! - [`verification`]: SSA-based semantic comparison of original and deobfuscated assemblies.
//! - [`compatibility`]: load and compare whole runtime corpora (Mono, .NET).
//! - [`analysis`], [`mono`]: analysis and runtime harnesses.
//! - [`tools`]: which external tools a test may go without, and running them with a timeout.
//! - [`TestTypeProvider`] with [`build_cfg`], [`build_ssa`] and [`build_ssa_with_handlers`]:
//!   SSA from assembled CIL.

// Test support panics on what it cannot set up and indexes what it built itself.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    missing_docs
)]

pub mod analysis;
pub mod builders;
pub mod compatibility;
mod crafted2;
#[cfg(feature = "emulation")]
pub mod emulation;
pub mod factories;
pub mod fixtures;
#[cfg(feature = "deobfuscation")]
pub mod framework;
pub mod helpers;
pub mod mono;
pub mod tools;
mod validator;
pub mod verification;
mod windowsbase;

use std::collections::BTreeMap;

pub use builders::*;
pub use crafted2::*;
pub use fixtures::{fixture, fixture_bytes};
pub use helpers::*;
pub use validator::*;
pub use windowsbase::*;

use crate::{
    analysis::{ControlFlowGraph, SsaConverter, SsaFunction, SsaType, TypeProvider},
    assembly::{decode_blocks, decode_blocks_with_handlers, InstructionAssembler},
    metadata::{
        method::{ExceptionHandler, Method},
        signatures::SignatureLocalVariable,
        token::Token,
    },
    CilObject, Result,
};

/// Test-only type provider that declares explicit types for synthetic CIL.
///
/// Used by converter tests that build SSA from inline CIL without real
/// assembly metadata. The test author explicitly chooses this provider
/// to declare "all args and locals in this test are I32."
pub struct TestTypeProvider {
    num_args: usize,
    num_locals: usize,
    /// Locals declared with a type other than `I32`.
    local_types: BTreeMap<u16, SsaType>,
    /// Whether the body sets `.locals init`.
    locals_init: bool,
}

impl TestTypeProvider {
    /// Creates a new test type provider with the given argument and local counts.
    #[must_use]
    pub fn new(num_args: usize, num_locals: usize) -> Self {
        Self {
            num_args,
            num_locals,
            local_types: BTreeMap::new(),
            locals_init: true,
        }
    }

    /// Declares local `idx` with `ty` instead of `I32`.
    #[must_use]
    pub fn with_local_type(mut self, idx: u16, ty: SsaType) -> Self {
        self.local_types.insert(idx, ty);
        self
    }

    /// Declares a body without `.locals init`.
    #[must_use]
    pub fn without_locals_init(mut self) -> Self {
        self.locals_init = false;
        self
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
        if let Some(ty) = self.local_types.get(&idx) {
            ty.clone()
        } else if (idx as usize) < self.num_locals {
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

    fn locals_zero_initialized(&self) -> bool {
        self.locals_init
    }
}

/// Build a control flow graph (and raw bytecode) from assembled CIL.
///
/// Returns both the bytecode vector and the CFG so callers that need
/// the original bytes for round-trip verification can keep them.
pub fn build_cfg(assembler: InstructionAssembler) -> Result<(Vec<u8>, ControlFlowGraph<'static>)> {
    let (bytecode, _max_stack, _) = assembler.finish()?;
    let blocks = decode_blocks(&bytecode, 0, 0x1000, Some(bytecode.len()))?;
    let cfg = ControlFlowGraph::from_basic_blocks(blocks)?;
    Ok((bytecode, cfg))
}

/// Build SSA form from a control flow graph, every argument and local an `I32`.
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
        Vec::new(),
    )
}

/// Build SSA from assembled CIL with exception clauses, the way a method body
/// is: decoded from each handler entry as well as the first instruction, with
/// the clauses mapped onto the blocks and handed to construction.
pub fn build_ssa_with_handlers(
    bytecode: &[u8],
    clauses: &[ExceptionHandler],
    num_args: usize,
    num_locals: usize,
) -> Result<SsaFunction> {
    let blocks = decode_blocks_with_handlers(bytecode, 0, 0x1000, Some(bytecode.len()), clauses)?;
    let handlers = Method::ssa_handlers_for_clauses(clauses, &blocks)?;
    let cfg = ControlFlowGraph::from_basic_blocks(blocks)?;
    SsaConverter::build(
        &cfg,
        num_args,
        num_locals,
        &TestTypeProvider::new(num_args, num_locals),
        handlers,
    )
}
