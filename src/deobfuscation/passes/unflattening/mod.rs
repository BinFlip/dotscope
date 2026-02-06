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
//! 1. **Detection**: Identify CFF patterns via structural analysis (dominance, SCCs, back-edges)
//! 2. **State Variable Identification**: Find the variable controlling dispatch via dataflow
//! 3. **Dispatcher Classification**: Determine dispatcher type (switch, if-else chain, etc.)
//! 4. **State Resolution**: Resolve state values using constant propagation, symbolic execution, or Z3
//! 5. **Graph Construction**: Build state transition graph from resolved values
//! 6. **CFG Reconstruction**: Convert state graph back to clean control flow
//!
//! # Design Principles
//!
//! - **Structure-based detection**: Uses graph properties, not opcode patterns
//! - **Tiered state resolution**: Fast path (const prop) with fallback to symbolic/Z3
//! - **Graceful degradation**: Works partially even when full recovery isn't possible
//! - **Clean separation**: Each phase is isolated for testability

mod detection;
mod dispatcher;
mod reconstruction;
mod statevar;
mod tracer;

pub use reconstruction::{apply_patch_plan, extract_patch_plan};
pub use tracer::{trace_method_tree, TraceTree};

use std::sync::Arc;

use crate::{
    analysis::SsaFunction,
    deobfuscation::{context::AnalysisContext, pass::SsaPass},
    metadata::token::Token,
    CilObject, Result,
};

/// High-level API: Unflatten a method using tree-based tracing and patching.
///
/// This is the main entry point for the trace-based unflattening approach.
/// It traces the method, builds a tree of execution paths, and patches
/// the original SSA in place to remove CFF machinery.
///
/// # Arguments
///
/// * `ssa` - The SSA function to unflatten
/// * `config` - Configuration controlling tracing limits and behavior
///
/// # Returns
/// - `Ok(Some(ssa))` if unflattening succeeded (patched clone)
/// - `Ok(None)` if method doesn't appear to be CFF-protected
/// - `Err(...)` if an error occurred
pub fn unflatten_with_tree(
    ssa: &SsaFunction,
    config: &UnflattenConfig,
) -> Result<Option<SsaFunction>> {
    // Step 1: Trace the method into a tree
    let tree = trace_method_tree(ssa, config);

    // Step 2: Check if we found a dispatcher
    if tree.dispatcher.is_none() {
        return Ok(None);
    }

    // Step 3: Extract patch plan from the tree
    let plan = match extract_patch_plan(&tree) {
        Some(p) => p,
        None => {
            return Ok(None);
        }
    };

    // Step 4: Only proceed if there are state transitions to remove
    if plan.state_transitions_removed == 0 {
        return Ok(None);
    }

    // Step 5: Clone the SSA and apply patches
    let mut patched = ssa.clone();
    let _result = apply_patch_plan(&mut patched, &plan);

    Ok(Some(patched))
}

/// Configuration for the CFF reconstruction pass.
#[derive(Debug, Clone)]
pub struct UnflattenConfig {
    /// Maximum states to explore before giving up.
    ///
    /// CFF typically has dozens to hundreds of states. If we exceed this
    /// limit, the method likely has unusual structure or isn't CFF.
    pub max_states: usize,

    /// Enable Z3 solver for complex state encodings.
    ///
    /// When constant propagation can't resolve states, the solver can
    /// enumerate possible values. Disable for faster (but less complete) analysis.
    pub enable_solver: bool,

    /// Maximum solver time per query in milliseconds.
    ///
    /// Limits time spent on individual Z3 queries to prevent stalls.
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

    /// Maximum number of blocks to visit during tracing.
    ///
    /// Prevents infinite loops when tracing through the CFG. If exceeded,
    /// tracing stops with a `StopReason::MaxVisitsExceeded`.
    pub max_block_visits: usize,

    /// Maximum recursion depth for tree tracing.
    ///
    /// Prevents stack overflow when building the trace tree. Limits how
    /// deeply nested the tree can become from forking at user branches.
    pub max_tree_depth: usize,
}

impl Default for UnflattenConfig {
    fn default() -> Self {
        Self {
            max_states: 1000,
            enable_solver: true,
            solver_timeout_ms: 100,
            min_confidence: 0.6,
            max_eval_depth: 30,
            max_block_visits: 10000,
            max_tree_depth: 100,
        }
    }
}

impl UnflattenConfig {
    /// Creates a configuration optimized for ConfuserEx samples.
    ///
    /// ConfuserEx uses predictable arithmetic encoding that constant
    /// propagation can always resolve, so we can be more aggressive.
    #[must_use]
    pub fn confuserex() -> Self {
        Self {
            max_states: 500,
            enable_solver: false, // Not needed for ConfuserEx
            solver_timeout_ms: 50,
            min_confidence: 0.5,
            max_eval_depth: 25,
            max_block_visits: 5000,
            max_tree_depth: 75,
        }
    }

    /// Creates a configuration for aggressive analysis.
    ///
    /// Useful for heavily obfuscated code where detection may have
    /// lower confidence.
    #[must_use]
    pub fn aggressive() -> Self {
        Self {
            max_states: 2000,
            enable_solver: true,
            solver_timeout_ms: 200,
            min_confidence: 0.4,
            max_eval_depth: 50,
            max_block_visits: 20000,
            max_tree_depth: 150,
        }
    }
}

/// Control flow flattening reconstruction pass.
///
/// This pass detects and reverses control flow flattening, a common
/// obfuscation technique that converts structured control flow into
/// a state machine.
///
/// # Example
///
/// ```rust,no_run
/// use dotscope::deobfuscation::passes::{CffReconstructionPass, UnflattenConfig};
///
/// let pass = CffReconstructionPass::new(UnflattenConfig::default());
/// // Pass is used by the deobfuscation engine
/// ```
pub struct CffReconstructionPass {
    config: UnflattenConfig,
}

impl Default for CffReconstructionPass {
    fn default() -> Self {
        Self::new(UnflattenConfig::default())
    }
}

impl CffReconstructionPass {
    /// Creates a new CFF reconstruction pass with the given configuration.
    #[must_use]
    pub fn new(config: UnflattenConfig) -> Self {
        Self { config }
    }

    /// Creates a pass with default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::default()
    }
}

impl SsaPass for CffReconstructionPass {
    fn name(&self) -> &'static str {
        "cff-reconstruction"
    }

    fn description(&self) -> &'static str {
        "Recovers original control flow from flattened state machine patterns"
    }

    fn run_on_method(
        &self,
        ssa: &mut SsaFunction,
        method_token: Token,
        ctx: &AnalysisContext,
        _assembly: &Arc<CilObject>,
    ) -> Result<bool> {
        // Skip if already unflattened in a previous pass
        if ctx.unflattened_dispatchers.contains(&method_token) {
            return Ok(false);
        }

        // Use the new tree-based patch approach for CFF unflattening.
        // This traces execution paths, builds a tree of all possibilities,
        // then patches the original SSA in place by:
        // 1. Redirecting jumps that go to the dispatcher to their actual targets
        // 2. Filtering out state-tainted instructions (CFF machinery)
        //
        // This approach is more reliable than the old reconstruction because:
        // - It preserves the original SSA structure (variables, phi nodes)
        // - It handles user branches correctly (non-state-dependent conditions)
        // - DCE naturally cleans up unreachable dispatcher code
        match unflatten_with_tree(ssa, &self.config)? {
            Some(mut patched) => {
                // After CFF unflattening, the CFG structure has changed significantly.
                // Rebuild SSA form to ensure PHI nodes are correct for the new CFG.
                patched.rebuild_ssa();

                *ssa = patched;

                // Mark as successfully unflattened
                ctx.unflattened_dispatchers.insert(method_token);
                ctx.mark_dispatcher(method_token);

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
        deobfuscation::{
            passes::unflattening::{detection::CffDetector, dispatcher::Dispatcher},
            DeobfuscationEngine, EngineConfig,
        },
        metadata::token::Token,
        CilObject,
    };

    fn create_dispatcher_ssa() -> (SsaFunction, Dispatcher) {
        let mut ssa = SsaFunction::new(0, 1);
        let state_var = SsaVarId::new();
        let switch_var = SsaVarId::new();

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
        SsaConverter::build(cfg, num_args, num_locals, None)
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
        let mut engine = DeobfuscationEngine::new(config);
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

        // After unflattening, the CFF dispatcher switch is eliminated but the
        // user's original switch (on the input argument) should be preserved.
        // The user's switch controls input-dependent flow which is semantically
        // meaningful and should not be flattened.
        let final_switch_count = count_switches(&ssa);
        assert_eq!(
            final_switch_count, 1,
            "User's original switch should be preserved, only CFF switch eliminated"
        );

        Ok(())
    }
}
