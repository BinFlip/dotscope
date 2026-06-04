//! Control flow unflattening pass.
//!
//! This module recovers original control flow from flattened code, where
//! structured control flow (if/else, loops, switches) has been transformed
//! into a state machine with a central dispatcher.
//!
//! # Supported Patterns
//!
//! The unflattening algorithm is generic and handles various CFF implementations:
//!
//! - **ConfuserEx**: Switch-based dispatcher with arithmetic state encoding
//! - **OLLVM**: If-else chain dispatchers with XOR-based state
//! - **Custom**: Any pattern matching the structural CFF signature
//!
//! # Algorithm Overview
//!
//! 1. **Detection** ([`detection`]): Identify CFF dispatchers via structural graph
//!    analysis — dominance, predecessor counts, back-edge ratios, method coverage
//! 2. **State Variable Identification** ([`statevar`]): Trace from the switch
//!    instruction backwards through the SSA to find the PHI node carrying state
//! 3. **Dispatcher Classification** ([`dispatcher`]): Determine type (switch with
//!    optional XOR/modulo transform, if-else chain, computed jump)
//! 4. **Tracing** ([`tracer`]): Evaluate the method from entry, following state
//!    transitions through the dispatcher while forking at user branches to build
//!    a tree of all execution paths
//! 5. **Reconstruction** ([`reconstruction`]): Extract a patch plan from the trace
//!    tree (redirects, block clones, state instruction removal) and apply it to
//!    the SSA, eliminating the dispatcher
//!
//! # Design Principles
//!
//! - **Structure-based detection**: Uses graph properties, not opcode patterns
//! - **Concrete evaluation**: SSA evaluator resolves state transitions at trace
//!   time — no solver needed for standard arithmetic encodings
//! - **Graceful degradation**: Works partially even when full recovery isn't possible
//! - **Clean separation**: Each phase is isolated for testability

mod detection;
mod dispatcher;
mod reconstruction;
mod statevar;
mod tracer;

pub use detection::CffDetector;
pub use dispatcher::Dispatcher;
pub use reconstruction::{apply_patch_plan, extract_patch_plan, merge_patch_plans};

use std::sync::Arc;

use dashmap::DashSet;
use rayon::prelude::*;

use std::collections::HashMap;

use crate::{
    analysis::{CilTarget, MethodRef, SsaFunction},
    compiler::{CompilerContext, PassCapability, SsaPass},
    deobfuscation::{
        config::DetectionWeights,
        context::AnalysisContext,
        passes::unflattening::tracer::{trace_for_dispatcher, TracedDispatcher},
    },
    metadata::{token::Token, typesystem::PointerSize},
    CilObject,
};

/// High-level API: Unflatten a method using tree-based tracing and patching.
///
/// This is the main entry point for the trace-based unflattening approach.
/// It detects ALL CFF dispatchers in the method (there may be independent
/// dispatchers in different exception handler regions), traces each one
/// independently, merges the patch plans, and applies them all at once
/// before a single `rebuild_ssa()`. This avoids the block renumbering
/// corruption that occurs when dispatchers are processed iteratively
/// with intermediate SSA rebuilds.
///
/// # Arguments
///
/// * `ssa` - The SSA function to unflatten.
/// * `config` - Configuration controlling tracing limits and behavior.
/// * `assembly` - Optional assembly for predicate method resolution during tracing.
///
/// # Returns
/// - `Some(ssa)` if unflattening succeeded (patched clone)
/// - `None` if method doesn't appear to be CFF-protected
pub fn unflatten(
    ssa: &SsaFunction,
    config: &UnflattenConfig,
    assembly: Option<&CilObject>,
) -> Option<SsaFunction> {
    let mut detector = CffDetector::with_config(ssa, config);
    let dispatchers: Vec<_> = detector
        .detect_all_dispatchers()
        .into_iter()
        .filter(|d| d.confidence >= config.min_confidence)
        .collect();

    unflatten_with_dispatchers(ssa, config, assembly, dispatchers)
}

/// Unflatten a method using pre-detected dispatchers.
///
/// Like [`unflatten`], but skips the detection phase and uses the provided
/// dispatchers directly. This is used when the [`GenericFlattening`] technique
/// has already run [`CffDetector`] during `detect_ssa()` and stored the results
/// in [`FlatteningFindings`].
///
/// [`GenericFlattening`]: crate::deobfuscation::techniques::generic::GenericFlattening
/// [`FlatteningFindings`]: crate::deobfuscation::techniques::generic::flattening::FlatteningFindings
///
/// # Arguments
///
/// * `ssa` - The SSA function to unflatten.
/// * `config` - Configuration controlling tracing limits and behavior.
/// * `assembly` - Optional assembly for predicate method resolution during tracing.
/// * `dispatchers` - Pre-detected dispatchers (already confidence-filtered).
///
/// # Returns
/// - `Some(ssa)` if unflattening succeeded (patched clone)
/// - `None` if no dispatchers provided or tracing produced no changes
pub fn unflatten_with_dispatchers(
    ssa: &SsaFunction,
    config: &UnflattenConfig,
    assembly: Option<&CilObject>,
    dispatchers: Vec<Dispatcher>,
) -> Option<SsaFunction> {
    if dispatchers.is_empty() {
        return None;
    }

    // Trace dispatchers in parallel and extract patch plans.
    // Each dispatcher trace is independent (shared &SsaFunction, own evaluator).
    // Pass other dispatcher block indices so forks at foreign dispatchers
    // don't consume tree depth budget (Problem A from §15.5).
    let all_dispatcher_blocks: Vec<usize> = dispatchers.iter().map(|d| d.block).collect();

    let plans: Vec<_> = dispatchers
        .par_iter()
        .filter_map(|d| {
            let traced = TracedDispatcher {
                block: d.block,
                switch_var: d.switch_var,
                targets: d.cases.clone(),
                default: d.default,
                state_var: d.state_phi,
                initial_state: d.initial_state,
            };

            let others: Vec<usize> = all_dispatcher_blocks
                .iter()
                .copied()
                .filter(|&b| b != d.block)
                .collect();
            let tree = trace_for_dispatcher(ssa, config, assembly, traced, &others);

            tree.dispatcher.as_ref()?;

            extract_patch_plan(&tree, ssa).filter(|plan| plan.state_transitions_removed > 0)
        })
        .collect();

    if plans.is_empty() {
        return None;
    }

    // Step 3: Merge all patch plans into a single combined plan
    let merged = merge_patch_plans(plans);

    if merged.state_transitions_removed == 0 {
        return None;
    }

    // Step 4: Clone the SSA and apply the combined patches once
    let mut patched = ssa.clone();
    let _result = apply_patch_plan(&mut patched, &merged);

    // Note: we do NOT reject based on dispatcher_still_needed. With multiple
    // dispatchers, some may be fully resolved while others are only partial
    // (e.g., handler CFF that depends on the outer CFF state). apply_patch_plan
    // already handles this correctly: it only clears dispatchers that are fully
    // resolved, leaving partial ones intact for later passes or as harmless
    // residual. Rejecting the entire result would prevent the fully-resolved
    // main body CFF from being applied.

    Some(patched)
}

/// Configuration for the CFF reconstruction pass.
#[derive(Debug, Clone)]
pub struct UnflattenConfig {
    /// Maximum states to explore before giving up.
    ///
    /// CFF typically has dozens to hundreds of states. If we exceed this
    /// limit, the method likely has unusual structure or isn't CFF.
    pub max_states: usize,

    /// Reserved: enable solver for complex state encodings.
    ///
    /// Placeholder for future solver integration. Currently unused — state
    /// resolution relies entirely on concrete evaluation via the SSA evaluator.
    pub enable_solver: bool,

    /// Reserved: maximum solver time per query in milliseconds.
    ///
    /// Placeholder for future solver integration. Currently unused.
    pub solver_timeout_ms: u64,

    /// Minimum confidence score to attempt unflattening (0.0 - 1.0).
    ///
    /// Detection assigns confidence based on how strongly the method
    /// matches CFF patterns. Lower values catch more CFF but may
    /// produce false positives.
    pub min_confidence: f64,

    /// Maximum depth for constant propagation evaluation.
    ///
    /// Limits how deeply we trace through SSA definitions when
    /// evaluating state values.
    pub max_eval_depth: usize,

    /// Maximum BFS depth for back-edge transitive reachability check.
    ///
    /// Used in confidence scoring to determine if case blocks can
    /// transitively reach the dispatcher through intermediate blocks.
    pub max_backedge_depth: usize,

    /// Confidence scoring weights for CFF dispatcher detection.
    pub confidence_weights: DetectionWeights,

    /// Maximum number of blocks to visit during tracing.
    ///
    /// Prevents infinite loops when tracing through the CFG. If exceeded,
    /// tracing stops with a `StopReason::MaxVisitsExceeded`.
    pub max_block_visits: usize,

    /// Maximum nesting depth for the trace tree.
    ///
    /// Limits how deeply nested the tree can become from forking at user
    /// branches. Prevents exponential tree growth in methods with many
    /// independent conditionals.
    pub max_tree_depth: usize,

    /// Target pointer size for SSA evaluation.
    ///
    /// Derived from the PE header. Used by the SSA evaluator for
    /// pointer-sized arithmetic during tracing.
    pub pointer_size: PointerSize,
}

impl Default for UnflattenConfig {
    fn default() -> Self {
        Self {
            max_states: 1000,
            enable_solver: true,
            solver_timeout_ms: 100,
            min_confidence: 0.6,
            max_eval_depth: 30,
            max_block_visits: 50000,
            max_tree_depth: 500,
            pointer_size: PointerSize::Bit32,
            max_backedge_depth: 10,
            confidence_weights: DetectionWeights::default(),
        }
    }
}

impl UnflattenConfig {
    /// Creates a configuration optimized for ConfuserEx samples.
    ///
    /// ConfuserEx uses predictable arithmetic encoding that constant
    /// propagation can always resolve, so we can be more aggressive
    /// with lower state limits and no solver.
    ///
    /// # Returns
    ///
    /// An `UnflattenConfig` with reduced limits and the solver disabled.
    #[must_use]
    pub fn confuserex() -> Self {
        Self {
            max_states: 500,
            enable_solver: false,
            solver_timeout_ms: 50,
            min_confidence: 0.5,
            max_eval_depth: 25,
            max_block_visits: 5000,
            max_tree_depth: 75,
            ..Self::default()
        }
    }

    /// Creates a configuration for aggressive analysis.
    ///
    /// Useful for heavily obfuscated code where detection may have
    /// lower confidence. Uses higher limits and a lower confidence
    /// threshold to catch more CFF patterns at the cost of longer
    /// analysis time.
    ///
    /// # Returns
    ///
    /// An `UnflattenConfig` with increased limits and the solver enabled.
    #[must_use]
    pub fn aggressive() -> Self {
        Self {
            max_states: 2000,
            solver_timeout_ms: 200,
            min_confidence: 0.4,
            max_eval_depth: 50,
            max_block_visits: 20000,
            max_tree_depth: 150,
            max_backedge_depth: 15,
            ..Self::default()
        }
    }
}

/// Control flow flattening reconstruction pass.
///
/// This pass detects and reverses control flow flattening, a common
/// obfuscation technique that converts structured control flow into
/// a state machine.
///
/// When detection-phase findings are available, the pass uses pre-computed
/// dispatchers directly instead of re-running detection. This avoids duplicate
/// structural analysis (dominance, SCCs, confidence scoring) for methods
/// already analyzed during the detection phase's SSA pass.
pub struct CffReconstructionPass {
    config: UnflattenConfig,
    /// Successfully unflattened dispatcher methods (shared with deob engine).
    unflattened_dispatchers: Arc<DashSet<Token>>,
    /// All detected dispatcher methods (shared with deob engine).
    dispatchers: Arc<DashSet<Token>>,
    /// Pre-detected dispatchers from the detection phase (method → dispatchers).
    /// When populated, `run_on_method` uses these instead of re-running detection.
    pre_detected: HashMap<Token, Vec<Dispatcher>>,
}

impl Default for CffReconstructionPass {
    fn default() -> Self {
        Self {
            config: UnflattenConfig::default(),
            unflattened_dispatchers: Arc::new(DashSet::new()),
            dispatchers: Arc::new(DashSet::new()),
            pre_detected: HashMap::new(),
        }
    }
}

impl CffReconstructionPass {
    /// Creates a new CFF reconstruction pass from an analysis context.
    ///
    /// Captures shared references to the context's dispatcher sets so the engine
    /// can inspect which dispatchers were found and unflattened after the pipeline.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The analysis context providing shared dispatcher tracking sets.
    /// * `config` - Configuration controlling tracing limits, confidence thresholds,
    ///   and solver usage.
    ///
    /// # Returns
    ///
    /// A new `CffReconstructionPass` ready for pipeline execution.
    #[must_use]
    pub fn new(ctx: &AnalysisContext, config: UnflattenConfig) -> Self {
        Self {
            config,
            unflattened_dispatchers: Arc::clone(&ctx.unflattened_dispatchers),
            dispatchers: Arc::clone(&ctx.dispatchers),
            pre_detected: HashMap::new(),
        }
    }

    /// Sets the pre-detected dispatchers from the detection phase.
    ///
    /// When set, `run_on_method` uses these dispatchers directly instead of
    /// re-running the internal CFF detector, avoiding duplicate work.
    ///
    /// # Arguments
    ///
    /// * `pre_detected` - Map from method token to pre-detected dispatchers.
    #[must_use]
    pub fn with_pre_detected(mut self, pre_detected: HashMap<Token, Vec<Dispatcher>>) -> Self {
        self.pre_detected = pre_detected;
        self
    }

    /// Creates a pass with default configuration and standalone state.
    ///
    /// Suitable for testing or standalone usage without an analysis context.
    /// The pass uses its own internal dispatcher tracking sets rather than
    /// sharing them with an [`AnalysisContext`].
    ///
    /// # Returns
    ///
    /// A new `CffReconstructionPass` with default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::default()
    }
}

impl SsaPass<CilTarget, CompilerContext> for CffReconstructionPass {
    fn name(&self) -> &'static str {
        "cff-reconstruction"
    }

    fn description(&self) -> &'static str {
        "Recovers original control flow from flattened state machine patterns"
    }

    fn provides(&self) -> &[PassCapability] {
        &[PassCapability::RestoredControlFlow]
    }

    fn requires(&self) -> &[PassCapability] {
        &[PassCapability::ResolvedStaticFields]
    }

    fn should_run(&self, method: &MethodRef, _host: &CompilerContext) -> bool {
        // Skip methods already unflattened and also skip methods that were never
        // detected as having dispatchers.
        !self.unflattened_dispatchers.contains(&method.0)
            && self
                .pre_detected
                .get(&method.0)
                .is_some_and(|d| !d.is_empty())
    }

    fn run_on_method(
        &self,
        ssa: &mut SsaFunction,
        method: &MethodRef,
        host: &CompilerContext,
    ) -> analyssa::Result<bool> {
        let assembly_arc = host
            .assembly()
            .ok_or_else(|| analyssa::Error::new("CffReconstructionPass requires an assembly"))?;
        let assembly: &CilObject = &assembly_arc;
        let ctx = host;
        let method_token = method.0;
        let mut config = self.config.clone();
        config.pointer_size = PointerSize::from_is_64bit(assembly.file().pe().is_64bit);

        // Use pre-detected dispatcher block indices from detect_ssa phase, but
        // refresh variable IDs from the current SSA. Earlier passes (opaque field
        // predicates, etc.) trigger rebuild_ssa() which reindexes variables, making
        // the original SsaVarId values stale.
        let dispatchers: Vec<Dispatcher> = self
            .pre_detected
            .get(&method_token)
            .map(|pre| pre.iter().filter_map(|d| d.refresh(ssa)).collect())
            .unwrap_or_default();

        match unflatten_with_dispatchers(ssa, &config, Some(assembly), dispatchers) {
            Some(mut patched) => {
                patched.rebuild_ssa()?;

                *ssa = patched;

                // Mark as successfully unflattened (kept for reporting)
                self.unflattened_dispatchers.insert(method_token);
                self.dispatchers.insert(method_token);
                ctx.no_inline.insert(method_token);

                // Clear any cached known values since SSA changed
                ctx.clear_known_values(method_token);

                Ok(true)
            }
            None => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, LazyLock};

    use crate::{
        analysis::{
            ControlFlowGraph, PhiNode, PhiOperand, SsaBlock, SsaConverter, SsaFunction,
            SsaInstruction, SsaOp, SsaVarId, VariableOrigin,
        },
        assembly::{decode_blocks, InstructionAssembler},
        deobfuscation::passes::unflattening::{detection::CffDetector, dispatcher::Dispatcher},
        deobfuscation::{DeobfuscationEngine, EngineConfig},
        metadata::token::Token,
        test::TestTypeProvider,
        CilObject,
    };

    fn create_dispatcher_ssa() -> (SsaFunction, Dispatcher) {
        let mut ssa = SsaFunction::new(0, 1);
        let state_var = SsaVarId::from_index(0);
        let switch_var = SsaVarId::from_index(1);

        // B0: entry -> jump to dispatcher
        let mut b0 = SsaBlock::new(0);
        b0.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 1 }));
        ssa.add_block(b0);

        // B1: dispatcher with switch
        let mut b1 = SsaBlock::new(1);
        let mut phi = PhiNode::new(state_var, VariableOrigin::Local(0));
        phi.add_operand(PhiOperand::new(state_var, 0));
        b1.add_phi(phi);
        b1.add_instruction(SsaInstruction::synthetic(SsaOp::Copy {
            dest: switch_var,
            src: state_var,
        }));
        b1.add_instruction(SsaInstruction::synthetic(SsaOp::Switch {
            value: switch_var,
            targets: vec![2, 3],
            default: 4,
        }));
        ssa.add_block(b1);

        // B2, B3: case blocks that jump back to dispatcher
        for i in 2..=3 {
            let mut b = SsaBlock::new(i);
            b.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 1 }));
            ssa.add_block(b);
        }

        // B4: default/exit
        let mut b4 = SsaBlock::new(4);
        b4.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: None }));
        ssa.add_block(b4);

        let dispatcher = Dispatcher::new(1, switch_var, vec![2, 3], 4)
            .with_state_phi(state_var)
            .with_confidence(1.0);

        (ssa, dispatcher)
    }

    #[test]
    fn test_detect_dispatcher_finds_switch_with_back_edge() {
        let (ssa, _) = create_dispatcher_ssa();

        // Use CffDetector to detect the dispatcher
        let mut detector = CffDetector::new(&ssa);
        let detected = detector.detect_best();

        assert!(detected.is_some());
        let candidate = detected.unwrap();
        assert_eq!(candidate.block, 1);
    }

    /// Build CFG from assembled bytecode.
    fn build_cfg(assembler: InstructionAssembler) -> crate::Result<ControlFlowGraph<'static>> {
        let (bytecode, _max_stack, _) = assembler.finish()?;
        let blocks = decode_blocks(&bytecode, 0, 0x1000, Some(bytecode.len()))?;
        ControlFlowGraph::from_basic_blocks(blocks)
    }

    /// Build SSA from a control flow graph.
    fn build_ssa(
        cfg: &ControlFlowGraph<'_>,
        num_args: usize,
        num_locals: usize,
    ) -> crate::Result<SsaFunction> {
        SsaConverter::build(
            cfg,
            num_args,
            num_locals,
            &TestTypeProvider::new(num_args, num_locals),
        )
    }

    /// Check if SSA has a switch instruction (indicates CFF dispatcher).
    fn has_switch(ssa: &SsaFunction) -> bool {
        for block in ssa.blocks() {
            for instr in block.instructions() {
                if matches!(instr.op(), SsaOp::Switch { .. }) {
                    return true;
                }
            }
        }
        false
    }

    /// Count switch instructions in SSA.
    fn count_switches(ssa: &SsaFunction) -> usize {
        let mut count = 0;
        for block in ssa.blocks() {
            for instr in block.instructions() {
                if matches!(instr.op(), SsaOp::Switch { .. }) {
                    count += 1;
                }
            }
        }
        count
    }

    /// Run the full deobfuscation pipeline on an SSA function.
    ///
    /// This uses `DeobfuscationEngine::process_ssa` to run all passes
    /// including unflattening and DCE in the proper order.
    fn run_full_deobfuscation(ssa: &mut SsaFunction) -> crate::Result<()> {
        // Use LazyLock to load the assembly only once across all tests
        static TEST_ASSEMBLY: LazyLock<Arc<CilObject>> = LazyLock::new(|| {
            Arc::new(
                CilObject::from_path("tests/samples/crafted_2.exe")
                    .expect("Failed to load test assembly"),
            )
        });

        let config = EngineConfig::default();
        let engine = DeobfuscationEngine::new(config);
        let token = Token::new(0x06000001); // Synthetic method token
        engine.process_ssa(&TEST_ASSEMBLY, ssa, token)?;
        Ok(())
    }

    /// Test: Simple CFF pattern with 3 cases.
    ///
    /// This is a simplified version of CFF that has:
    /// - Entry block that initializes state and jumps to dispatcher
    /// - Dispatcher that computes (state ^ XOR) % 3 and switches
    /// - 3 case blocks that update state and jump back to dispatcher
    /// - Exit via default case
    ///
    /// Original semantics: sets local0 = 1, then = 2, then = 3, then returns.
    #[test]
    fn test_unflatten_simple_cff_pattern() -> crate::Result<()> {
        // Build CFF-obfuscated bytecode:
        //
        // Entry (block 0):
        //   ldc.i4 INIT_STATE  ; initial state that maps to case 0
        //   br dispatcher
        //
        // Dispatcher (block 1):
        //   dup
        //   stloc.2            ; save state in local2
        //   ldc.i4 XOR_KEY
        //   xor
        //   ldc.i4.3
        //   rem.un
        //   switch (case0, case1, case2)
        //   br exit            ; default -> exit
        //
        // Case 0: ldc.i4.1, stloc.0, compute_next_state, br dispatcher
        // Case 1: ldc.i4.2, stloc.0, compute_next_state, br dispatcher
        // Case 2: ldc.i4.3, stloc.0, br exit
        //
        // Exit: ret

        // For simplicity, use XOR_KEY = 0 so state directly maps to case index
        // This means: state 0 -> case 0, state 1 -> case 1, state 2 -> case 2
        // After unflattening, the flow should be: case0 -> case1 -> case2 -> exit

        let mut asm = InstructionAssembler::new();
        asm
            // Entry block: push initial state (0), go to dispatcher
            .ldc_i4(0)? // state = 0 -> case 0
            .br("dispatcher")?
            // Dispatcher block
            .label("dispatcher")?
            .dup()? // duplicate state for switch
            .stloc_s(2)? // save to local 2
            .ldc_i4(0)? // XOR key = 0 (identity)
            .xor()?
            .ldc_i4(3)? // MOD 3
            .rem_un()?
            .switch(&["case0", "case1", "case2"])?
            .br("exit")? // default -> exit
            // Case 0: set local0 = 1, state = 1, jump back
            .label("case0")?
            .ldc_i4(1)?
            .stloc_0()?
            .ldc_i4(1)? // next state = 1 -> case 1
            .br("dispatcher")?
            // Case 1: set local0 = 2, state = 2, jump back
            .label("case1")?
            .ldc_i4(2)?
            .stloc_0()?
            .ldc_i4(2)? // next state = 2 -> case 2
            .br("dispatcher")?
            // Case 2: set local0 = 3, go to exit
            .label("case2")?
            .ldc_i4(3)?
            .stloc_0()?
            .br("exit")?
            // Exit
            .label("exit")?
            .ret()?;

        let cfg = build_cfg(asm)?;
        let mut ssa = build_ssa(&cfg, 0, 3)?; // 0 args, 3 locals (local0, local1, local2)

        // Verify dispatcher is detected
        assert!(has_switch(&ssa), "Should have switch before unflattening");
        let initial_switch_count = count_switches(&ssa);
        assert!(initial_switch_count > 0, "Should have at least one switch");

        // Run full deobfuscation pipeline (includes unflattening + DCE)
        run_full_deobfuscation(&mut ssa)?;

        // After full pipeline, the CFF dispatcher switch should be eliminated
        let final_switch_count = count_switches(&ssa);
        assert_eq!(
            final_switch_count, 0,
            "CFF switch should be eliminated after deobfuscation"
        );

        Ok(())
    }

    /// Test: DemoLoop - EXACT 1:1 reproduction from monodis of mkaring_controlflow.exe
    ///
    /// From ControlFlowDemo::DemoLoop (int32 iterations)
    /// .locals init (int32 V_0, int32 V_1, unsigned int32 V_2)
    ///
    /// Key structure:
    /// - IL_0000-IL_0001: sum = 0
    /// - IL_0002: ldc.i4 -781784372 (init state, also case5 target)
    /// - IL_0007: ldc.i4 -576502913 (XOR key - cases jump HERE)
    /// - IL_000c-IL_0011: xor, dup, stloc.2, ldc.i4.7, rem.un, switch
    /// - Cases compute next state and jump back to IL_0007
    #[test]
    fn test_unflatten_demoloop_exact() -> crate::Result<()> {
        // EXACT IL from monodis:
        // IL_0000:  ldc.i4.0
        // IL_0001:  stloc.0
        // IL_0002:  ldc.i4 -781784372      <- case5 jumps here
        // IL_0007:  ldc.i4 -576502913      <- dispatcher entry (cases jump here)
        // IL_000c:  xor
        // IL_000d:  dup
        // IL_000e:  stloc.2
        // IL_000f:  ldc.i4.7
        // IL_0010:  rem.un
        // IL_0011:  switch (case0, case1, case2, case3, exit, init_state, case6)
        // IL_0032:  br.s exit              (default)
        //
        // case0 (IL_0034): i++, state update, br IL_0007
        // case1 (IL_0052): i=1, state update, br IL_0007
        // case2 (IL_0078): output, state update, br IL_0007
        // case3 (IL_0047): sum+=i, new state, br IL_0007
        // case5 (IL_0002): init_state - falls through to IL_0007
        // case6 (IL_0063): loop condition, br IL_0007

        let mut asm = InstructionAssembler::new();
        asm
            // IL_0000: ldc.i4.0
            // IL_0001: stloc.0
            .ldc_i4_0()?
            .stloc_0()?
            // IL_0002: ldc.i4 -781784372 (init_state - case5 target)
            // Falls through to dispatcher_entry
            .label("init_state")?
            .ldc_i4(-781784372_i32)?
            // IL_0007: ldc.i4 -576502913 (dispatcher entry - cases jump here)
            // IL_000c: xor
            // IL_000d: dup
            // IL_000e: stloc.2
            // IL_000f: ldc.i4.7
            // IL_0010: rem.un
            // IL_0011: switch (...)
            .label("dispatcher_entry")?
            .ldc_i4(-576502913_i32)?
            .xor()?
            .dup()?
            .stloc_s(2)?
            .ldc_i4(7)?
            .rem_un()?
            .switch(&[
                "case0",
                "case1",
                "case2",
                "case3",
                "exit",
                "init_state",
                "case6",
            ])?
            // IL_0032: br.s exit (default)
            .br_s("exit")?
            // IL_0034: case0 - i++, state update
            // ldloc.1, ldc.i4.1, add, stloc.1
            // ldloc.2, ldc.i4 1975223132, mul, ldc.i4 483589312, xor
            // br.s IL_0007
            .label("case0")?
            .ldloc_1()?
            .ldc_i4_1()?
            .add()?
            .stloc_1()?
            .ldloc_s(2)?
            .ldc_i4(1975223132_i32)?
            .mul()?
            .ldc_i4(483589312_i32)?
            .xor()?
            .br_s("dispatcher_entry")?
            // IL_0047: case3 - sum += i
            // ldloc.0, ldloc.1, add, stloc.0
            // ldc.i4 -730624750
            // br.s IL_0007
            .label("case3")?
            .ldloc_0()?
            .ldloc_1()?
            .add()?
            .stloc_0()?
            .ldc_i4(-730624750_i32)?
            .br_s("dispatcher_entry")?
            // IL_0052: case1 - i = 1, state update
            // ldc.i4.1, stloc.1
            // ldloc.2, ldc.i4 -1381170983, mul, ldc.i4 -1625566633, xor
            // br.s IL_0007
            .label("case1")?
            .ldc_i4_1()?
            .stloc_1()?
            .ldloc_s(2)?
            .ldc_i4(-1381170983_i32)?
            .mul()?
            .ldc_i4(-1625566633_i32)?
            .xor()?
            .br_s("dispatcher_entry")?
            // IL_0063: case6 - loop condition
            // ldloc.1, ldarg.1, bgt.s IL_006f
            // ldc.i4 -654475495, dup, br.s IL_0075
            // IL_006f: ldc.i4 -1309138752, dup
            // IL_0075: pop, br.s IL_0007
            .label("case6")?
            .ldloc_1()?
            .ldarg_1()?
            .bgt_s("case6_false")?
            .ldc_i4(-654475495_i32)?
            .dup()?
            .br_s("case6_merge")?
            .label("case6_false")?
            .ldc_i4(-1309138752_i32)?
            .dup()?
            .label("case6_merge")?
            .pop()?
            .br_s("dispatcher_entry")?
            // IL_0078: case2 - output (using nop as placeholder for ldstr/call)
            // In real IL: ldstr, ldarg.1, box, ldloc.0, box, call Format, call WriteLine
            // ldloc.2, ldc.i4 -1166059892, mul, ldc.i4 -15245519, xor
            // br IL_0007
            .label("case2")?
            .nop()? // placeholder for output operations
            .ldloc_s(2)?
            .ldc_i4(-1166059892_i32)?
            .mul()?
            .ldc_i4(-15245519_i32)?
            .xor()?
            .br("dispatcher_entry")?
            // IL_00a5: exit - ret
            .label("exit")?
            .ret()?;

        let cfg = build_cfg(asm)?;
        let mut ssa = build_ssa(&cfg, 2, 3)?; // 2 args (this + iterations), 3 locals

        // Verify initial state - should have 1 CFF dispatcher switch
        assert!(has_switch(&ssa), "Should have switch before unflattening");
        let initial_switch_count = count_switches(&ssa);
        assert_eq!(initial_switch_count, 1, "Should have exactly 1 CFF switch");

        // Run full deobfuscation pipeline (includes unflattening + DCE)
        run_full_deobfuscation(&mut ssa)?;

        // After full pipeline, the CFF dispatcher switch should be eliminated
        let final_switch_count = count_switches(&ssa);
        assert_eq!(
            final_switch_count, 0,
            "CFF switch should be eliminated after deobfuscation"
        );

        Ok(())
    }

    /// Test: DemoIfElse - EXACT 1:1 reproduction from monodis of mkaring_controlflow.exe
    ///
    /// From ControlFlowDemo::DemoIfElse (int32 value)
    /// .locals init (string V_0, unsigned int32 V_1)
    ///
    /// Key structure:
    /// - IL_0000-IL_0002: ldarg.1, ldc.i4.0, bge.s IL_0063 (check_zero)
    /// - IL_0004: ldc.i4 -1433646196 (init state for negative, case10 target)
    /// - IL_0009: ldc.i4 -2107303682 (XOR key - cases jump HERE)
    /// - IL_000e-IL_0014: xor, dup, stloc.1, ldc.i4.s 12, rem.un, switch
    /// - switch targets: output, check_zero, negative, zero, medium, exit_state, large, small, done, check_small, init_state, check_medium
    #[test]
    fn test_unflatten_demoifelse_exact() -> crate::Result<()> {
        // EXACT IL from monodis:
        // IL_0000:  ldarg.1
        // IL_0001:  ldc.i4.0
        // IL_0002:  bge.s IL_0063           (check_zero)
        //
        // IL_0004:  ldc.i4 -1433646196      <- init_state (case10 target)
        // IL_0009:  ldc.i4 -2107303682      <- dispatcher entry (cases jump here)
        // IL_000e:  xor
        // IL_000f:  dup
        // IL_0010:  stloc.1
        // IL_0011:  ldc.i4.s 0x0c           (12)
        // IL_0013:  rem.un
        // IL_0014:  switch (12 targets)
        // IL_0049:  br IL_0133              (default -> done)
        //
        // Cases jump back to IL_0009 (dispatcher_entry)

        let mut asm = InstructionAssembler::new();
        asm
            // IL_0000: ldarg.1
            // IL_0001: ldc.i4.0
            // IL_0002: bge.s IL_0063 (check_zero)
            .ldarg_1()?
            .ldc_i4_0()?
            .bge_s("check_zero")?
            // IL_0004: ldc.i4 -1433646196 (init_state - case10 target)
            // Falls through to dispatcher_entry
            .label("init_state")?
            .ldc_i4(-1433646196_i32)?
            // IL_0009: ldc.i4 -2107303682 (dispatcher entry)
            // IL_000e: xor
            // IL_000f: dup
            // IL_0010: stloc.1
            // IL_0011: ldc.i4.s 12
            // IL_0013: rem.un
            // IL_0014: switch (...)
            .label("dispatcher_entry")?
            .ldc_i4(-2107303682_i32)?
            .xor()?
            .dup()?
            .stloc_1()?
            .ldc_i4(12)?
            .rem_un()?
            .switch(&[
                "output",
                "check_zero",
                "negative",
                "zero",
                "medium",
                "exit_state",
                "large",
                "small",
                "done",
                "check_small",
                "init_state",
                "check_medium",
            ])?
            // IL_0049: br IL_0133 (default -> done)
            .br("done")?
            // IL_004e: case2 - negative
            // ldstr "Negative", stloc.0
            // ldloc.1, ldc.i4 1606139385, mul, ldc.i4 -134536511, xor
            // br.s IL_0009
            .label("negative")?
            .ldc_i4(1)? // placeholder for ldstr "Negative"
            .stloc_0()?
            .ldloc_1()?
            .ldc_i4(1606139385_i32)?
            .mul()?
            .ldc_i4(-134536511_i32)?
            .xor()?
            .br_s("dispatcher_entry")?
            // IL_0063: case1 - check_zero
            // ldarg.1, brtrue.s IL_006e
            // ldc.i4 -61014635, dup, br.s IL_0074
            // IL_006e: ldc.i4 -1737504033, dup
            // IL_0074: pop, br.s IL_0009
            .label("check_zero")?
            .ldarg_1()?
            .brtrue_s("check_zero_nonzero")?
            .ldc_i4(-61014635_i32)?
            .dup()?
            .br_s("check_zero_merge")?
            .label("check_zero_nonzero")?
            .ldc_i4(-1737504033_i32)?
            .dup()?
            .label("check_zero_merge")?
            .pop()?
            .br_s("dispatcher_entry")?
            // IL_0077: case4 - medium positive
            // ldstr "Medium positive", stloc.0
            // ldloc.1, ldc.i4 -1112056451, mul, ldc.i4 -957501578, xor
            // br IL_0009
            .label("medium")?
            .ldc_i4(3)? // placeholder for ldstr "Medium positive"
            .stloc_0()?
            .ldloc_1()?
            .ldc_i4(-1112056451_i32)?
            .mul()?
            .ldc_i4(-957501578_i32)?
            .xor()?
            .br("dispatcher_entry")?
            // IL_008f: case7 - small positive
            // ldstr "Small positive", stloc.0
            // ldloc.1, ldc.i4 1822600615, mul, ldc.i4 972313123, xor
            // br IL_0009
            .label("small")?
            .ldc_i4(4)? // placeholder for ldstr "Small positive"
            .stloc_0()?
            .ldloc_1()?
            .ldc_i4(1822600615_i32)?
            .mul()?
            .ldc_i4(972313123_i32)?
            .xor()?
            .br("dispatcher_entry")?
            // IL_00a7: case9 - check_small condition
            // ldarg.1, ldc.i4.s 10, blt.s IL_00b4
            // ldc.i4 -6576863, dup, br.s IL_00ba
            // IL_00b4: ldc.i4 -904275411, dup
            // IL_00ba: pop, br IL_0009
            .label("check_small")?
            .ldarg_1()?
            .ldc_i4(10)?
            .blt_s("check_small_true")?
            .ldc_i4(-6576863_i32)?
            .dup()?
            .br_s("check_small_merge")?
            .label("check_small_true")?
            .ldc_i4(-904275411_i32)?
            .dup()?
            .label("check_small_merge")?
            .pop()?
            .br("dispatcher_entry")?
            // IL_00c0: case11 - check_medium condition
            // ldarg.1, ldc.i4.s 100, bge.s IL_00cd
            // ldc.i4 -1847017906, dup, br.s IL_00d3
            // IL_00cd: ldc.i4 -1069863352, dup
            // IL_00d3: pop, br IL_0009
            .label("check_medium")?
            .ldarg_1()?
            .ldc_i4(100)?
            .bge_s("check_medium_large")?
            .ldc_i4(-1847017906_i32)?
            .dup()?
            .br_s("check_medium_merge")?
            .label("check_medium_large")?
            .ldc_i4(-1069863352_i32)?
            .dup()?
            .label("check_medium_merge")?
            .pop()?
            .br("dispatcher_entry")?
            // IL_00d9: case0 - output
            // ldstr "Value {0} is: {1}", ldarg.1, box, ldloc.0, call Format, call WriteLine
            // ldc.i4 -1184376018
            // br IL_0009
            .label("output")?
            .nop()? // placeholder for output operations
            .ldc_i4(-1184376018_i32)?
            .br("dispatcher_entry")?
            // IL_00f9: case3 - zero
            // ldstr "Zero", stloc.0
            // ldloc.1, ldc.i4 -1658452976, mul, ldc.i4 -1485570506, xor
            // br IL_0009
            .label("zero")?
            .ldc_i4(2)? // placeholder for ldstr "Zero"
            .stloc_0()?
            .ldloc_1()?
            .ldc_i4(-1658452976_i32)?
            .mul()?
            .ldc_i4(-1485570506_i32)?
            .xor()?
            .br("dispatcher_entry")?
            // IL_0111: case5 - exit_state (state update only)
            // ldloc.1, ldc.i4 -1339746023, mul, ldc.i4 -1565321453, xor
            // br IL_0009
            .label("exit_state")?
            .ldloc_1()?
            .ldc_i4(-1339746023_i32)?
            .mul()?
            .ldc_i4(-1565321453_i32)?
            .xor()?
            .br("dispatcher_entry")?
            // IL_0123: case6 - large positive
            // ldstr "Large positive", stloc.0
            // ldc.i4 -546964346
            // br IL_0009
            .label("large")?
            .ldc_i4(5)? // placeholder for ldstr "Large positive"
            .stloc_0()?
            .ldc_i4(-546964346_i32)?
            .br("dispatcher_entry")?
            // IL_0133: case8 - done (ret)
            .label("done")?
            .ret()?;

        let cfg = build_cfg(asm)?;
        let mut ssa = build_ssa(&cfg, 2, 2)?; // 2 args (this + value), 2 locals

        // Verify initial state - should have 1 CFF dispatcher switch
        assert!(has_switch(&ssa), "Should have switch before unflattening");
        let initial_switch_count = count_switches(&ssa);
        assert_eq!(initial_switch_count, 1, "Should have exactly 1 CFF switch");

        // Run full deobfuscation pipeline (includes unflattening + DCE)
        run_full_deobfuscation(&mut ssa)?;

        // After full pipeline, the CFF dispatcher switch should be eliminated
        let final_switch_count = count_switches(&ssa);
        assert_eq!(
            final_switch_count, 0,
            "CFF switch should be eliminated after deobfuscation"
        );

        Ok(())
    }

    /// Test: DemoSwitch - EXACT 1:1 reproduction from monodis of mkaring_controlflow.exe
    ///
    /// From ControlFlowDemo::DemoSwitch (int32 choice)
    /// .locals init (string V_0, unsigned int32 V_1)
    ///
    /// This method has TWO switches:
    /// 1. Original user switch at IL_0000 (switch on arg1)
    /// 2. CFF dispatcher switch at IL_002a
    #[test]
    fn test_unflatten_demoswitch_exact() -> crate::Result<()> {
        // EXACT IL from monodis:
        // IL_0000:  ldarg.1
        // IL_0001:  switch (case0_nothing, case1_start, case2_process, case3_stop, case4_reset)
        //
        // IL_001a:  ldc.i4 1109748230       <- init_state (falls through)
        // IL_001f:  ldc.i4 1399323750       <- dispatcher entry (cases jump here)
        // IL_0024:  xor
        // IL_0025:  dup
        // IL_0026:  stloc.1
        // IL_0027:  ldc.i4.s 14
        // IL_0029:  rem.un
        // IL_002a:  switch (14 targets)
        // IL_0067:  br IL_013d              (default -> done)

        let mut asm = InstructionAssembler::new();
        asm
            // IL_0000: ldarg.1
            // IL_0001: switch (5 targets - original user switch)
            .ldarg_1()?
            .switch(&["nothing", "start", "process", "stop", "reset"])?
            // IL_001a: ldc.i4 1109748230 (init_state for default case)
            .label("init_state")?
            .ldc_i4(1109748230_i32)?
            // IL_001f: ldc.i4 1399323750 (dispatcher entry)
            .label("dispatcher_entry")?
            .ldc_i4(1399323750_i32)?
            .xor()?
            .dup()?
            .stloc_1()?
            .ldc_i4(14)?
            .rem_un()?
            .switch(&[
                "init_state",
                "state1",
                "process",
                "state3",
                "state4",
                "reset",
                "start",
                "stop",
                "state8",
                "done",
                "output",
                "nothing",
                "state12",
                "unknown",
            ])?
            .br("done")?
            // IL_006c: case7 - stop
            // ldstr "Stop", stloc.0, ldc.i4 1874087721, br.s IL_001f
            .label("stop")?
            .ldc_i4(4)? // placeholder for ldstr "Stop"
            .stloc_0()?
            .ldc_i4(1874087721_i32)?
            .br_s("dispatcher_entry")?
            // IL_0079: case3 - state update
            // ldloc.1, ldc.i4 2035784935, mul, ldc.i4 1232406471, xor, br.s IL_001f
            .label("state3")?
            .ldloc_1()?
            .ldc_i4(2035784935_i32)?
            .mul()?
            .ldc_i4(1232406471_i32)?
            .xor()?
            .br_s("dispatcher_entry")?
            // IL_0088: case11 - nothing
            // ldstr "Nothing", stloc.0, ldc.i4 1654581703, br.s IL_001f
            .label("nothing")?
            .ldc_i4(0)? // placeholder for ldstr "Nothing"
            .stloc_0()?
            .ldc_i4(1654581703_i32)?
            .br_s("dispatcher_entry")?
            // IL_0095: case10 - output
            // ldstr "Choice {0} means: {1}", ..., ldc.i4 1061947317, br IL_001f
            .label("output")?
            .nop()? // placeholder for output operations
            .ldc_i4(1061947317_i32)?
            .br("dispatcher_entry")?
            // IL_00b5: case13 - unknown
            // ldstr "Unknown", stloc.0, ldc.i4 827576000, br IL_001f
            .label("unknown")?
            .ldc_i4(6)? // placeholder for ldstr "Unknown"
            .stloc_0()?
            .ldc_i4(827576000_i32)?
            .br("dispatcher_entry")?
            // IL_00c5: case12 - state update
            .label("state12")?
            .ldloc_1()?
            .ldc_i4(1665283153_i32)?
            .mul()?
            .ldc_i4(-1691273355_i32)?
            .xor()?
            .br("dispatcher_entry")?
            // IL_00d7: case1 - state update
            .label("state1")?
            .ldloc_1()?
            .ldc_i4(2085043702_i32)?
            .mul()?
            .ldc_i4(964678200_i32)?
            .xor()?
            .br("dispatcher_entry")?
            // IL_00e9: case4 - state update
            .label("state4")?
            .ldloc_1()?
            .ldc_i4(355033724_i32)?
            .mul()?
            .ldc_i4(-844819946_i32)?
            .xor()?
            .br("dispatcher_entry")?
            // IL_00fb: case2 - process
            // ldstr "Process", stloc.0, ldc.i4 1649866638, br IL_001f
            .label("process")?
            .ldc_i4(2)? // placeholder for ldstr "Process"
            .stloc_0()?
            .ldc_i4(1649866638_i32)?
            .br("dispatcher_entry")?
            // IL_010b: case8 - state update
            .label("state8")?
            .ldloc_1()?
            .ldc_i4(1697020441_i32)?
            .mul()?
            .ldc_i4(464976312_i32)?
            .xor()?
            .br("dispatcher_entry")?
            // IL_011d: case5 - reset
            // ldstr "Reset", stloc.0, ldc.i4 588169916, br IL_001f
            .label("reset")?
            .ldc_i4(5)? // placeholder for ldstr "Reset"
            .stloc_0()?
            .ldc_i4(588169916_i32)?
            .br("dispatcher_entry")?
            // IL_012d: case6 - start
            // ldstr "Start", stloc.0, ldc.i4 1649866638, br IL_001f
            .label("start")?
            .ldc_i4(1)? // placeholder for ldstr "Start"
            .stloc_0()?
            .ldc_i4(1649866638_i32)?
            .br("dispatcher_entry")?
            // IL_013d: done (ret)
            .label("done")?
            .ret()?;

        let cfg = build_cfg(asm)?;
        let mut ssa = build_ssa(&cfg, 2, 2)?; // 2 args (this + choice), 2 locals

        // This method has 2 switches: user's original switch + CFF dispatcher
        assert!(has_switch(&ssa), "Should have switch before unflattening");
        let initial_switch_count = count_switches(&ssa);
        assert_eq!(
            initial_switch_count, 2,
            "Should have exactly 2 switches (user + CFF)"
        );

        // Run full deobfuscation pipeline (includes unflattening + DCE)
        run_full_deobfuscation(&mut ssa)?;

        // After unflattening, the CFF dispatcher switch is eliminated.
        // The user's original switch may also be folded if DCE + constant
        // propagation prove all case targets are equivalent (which happens
        // here because placeholders make all cases converge to the same path).
        let final_switch_count = count_switches(&ssa);
        assert!(
            final_switch_count < initial_switch_count,
            "At least the CFF switch should be eliminated (was {initial_switch_count}, now {final_switch_count})"
        );

        Ok(())
    }

    /// Test: NETReactor-style CFF where the state variable is one of many locals.
    ///
    /// Reproduces a bug where the optimizer corrupts the initial state value.
    /// The entry block sets local4 = 10 (state var) along with several other
    /// locals (local0..3 = various values). After optimization, local4 must
    /// still evaluate to 10 at the dispatcher, not be confused with another
    /// local's value.
    ///
    /// Pattern:
    ///   B0: ldc.i4 1; stloc.0     (local0 = 1)
    ///       ldc.i4 0; stloc.1     (local1 = 0)
    ///       ldc.i4 4; stloc.2     (local2 = 4)
    ///       ldc.i4 1; stloc.3     (local3 = 1)
    ///       ldc.i4 10; stloc.s 4  (local4 = 10, the STATE variable)
    ///       br dispatcher
    ///   dispatcher:
    ///       ldloc.s 4
    ///       switch (case0..case13)  ; 14 cases, state 10 -> case10
    ///       br exit                ; default -> exit
    ///   case10:
    ///       ldloc.0               ; use local0 (value 1) as a counter
    ///       ldc.i4 3; stloc.s 4   ; next state = 3
    ///       br dispatcher
    ///   case3:
    ///       ldloc.0
    ///       ldc.i4 4; stloc.s 4   ; next state = 4
    ///       br dispatcher
    ///   case4:
    ///       br exit
    ///   (other cases: nop + br dispatcher for padding)
    ///   exit: ret
    #[test]
    fn test_initial_state_preserved_with_multiple_locals() -> crate::Result<()> {
        let mut asm = InstructionAssembler::new();

        asm
            // Entry: initialize multiple locals then state var
            .ldc_i4(1)?
            .stloc(0)? // local0 = 1
            .ldc_i4(0)?
            .stloc(1)? // local1 = 0
            .ldc_i4(4)?
            .stloc(2)? // local2 = 4
            .ldc_i4(1)?
            .stloc(3)? // local3 = 1
            .ldc_i4(10)?
            .stloc_s(4)? // local4 = 10 (STATE VAR)
            .br("dispatcher")?
            // Dispatcher: switch on state var (local4)
            .label("dispatcher")?
            .ldloc_s(4)?
            .switch(&[
                "case0", "case1", "case2", "case3", "case4", "case5", "case6", "case7", "case8",
                "case9", "case10", "case11", "case12", "case13",
            ])?
            .br("exit")? // default -> exit
            // Case 10: the FIRST executed case (initial state = 10)
            // Uses local0, then transitions to state 3
            .label("case10")?
            .ldloc(0)?
            .pop()?
            .ldc_i4(3)?
            .stloc_s(4)? // next state = 3
            .br("dispatcher")?
            // Case 3: second step, transitions to state 4
            .label("case3")?
            .ldloc(0)?
            .pop()?
            .ldc_i4(4)?
            .stloc_s(4)? // next state = 4
            .br("dispatcher")?
            // Case 4: exits
            .label("case4")?
            .br("exit")?;

        // Padding cases: just jump back to dispatcher (dead in correct trace)
        for i in [0, 1, 2, 5, 6, 7, 8, 9, 11, 12, 13] {
            asm.label(&format!("case{i}"))?
                .nop()?
                .ldc_i4(0)?
                .stloc_s(4)? // state = 0 (doesn't matter)
                .br("dispatcher")?;
        }

        // Exit
        asm.label("exit")?.ret()?;

        let cfg = build_cfg(asm)?;
        // 0 args, 5 locals (local0..local4, local4 is state)
        let ssa = build_ssa(&cfg, 0, 5)?;

        // Verify detection finds the dispatcher with initial_state = 10
        let mut detector = CffDetector::new(&ssa);
        let detected = detector.detect_best();

        assert!(detected.is_some(), "CFF dispatcher should be detected");
        let dispatcher = detected.unwrap();

        assert_eq!(
            dispatcher.initial_state,
            Some(10),
            "Initial state must be 10 (from ldc.i4 10; stloc.s 4 in entry block). \
             If this fails, the detection or optimizer is corrupting the state variable \
             value by confusing it with another local's value (e.g., local3=1)."
        );

        // Now simulate what happens in the full pipeline:
        // 1. The opaque pred pass may modify branches in case blocks
        // 2. Optimizer runs (copy prop + DCE)
        // 3. rebuild_ssa() creates fresh SSA
        // The state variable must still be detectable with value 10.
        let mut ssa_mut = ssa;
        run_full_deobfuscation(&mut ssa_mut)?;

        // After the full pipeline, check if the CFF was properly unflattened.
        // If the initial state was corrupted (e.g., 10 → 1), the trace would
        // follow the wrong path (case 1 instead of case 10) and the switch
        // would remain.
        let remaining_switches = count_switches(&ssa_mut);
        assert_eq!(
            remaining_switches, 0,
            "CFF switch should be completely removed after unflattening. \
             If it remains, the trace likely followed the wrong initial state path. \
             The initial state should be 10 (case10 -> case3 -> case4 -> exit)."
        );

        Ok(())
    }
}
