//! ConfuserEx Constants Protection Detection and Decryption
//!
//! This module provides detection and decryption for ConfuserEx's constants
//! protection, which encrypts strings, numbers, and arrays in the assembly.
//!
//! # Source Code Analysis
//!
//! Based on analysis of the ConfuserEx source code at:
//! - `Confuser.Protections/Constants/ConstantProtection.cs` - Protection entry point
//! - `Confuser.Protections/Constants/EncodePhase.cs` - Constant encoding
//! - `Confuser.Protections/Constants/ReferenceReplacer.cs` - Call site replacement
//! - `Confuser.Protections/Constants/DynamicMode.cs` - Dynamic cipher mode
//! - `Confuser.Protections/Constants/CEContext.cs` - Context structure
//! - `Confuser.Runtime/Constant.cs` - Runtime decryption & CFGCtx
//!
//! # Protection Preset
//!
//! Constants protection is part of the **Normal** preset:
//! ```csharp
//! // From ConstantProtection.cs line 34:
//! public override ProtectionPreset Preset {
//!     get { return ProtectionPreset.Normal; }
//! }
//! ```
//!
//! # Architecture Overview
//!
//! ## Encoding Phase
//!
//! 1. All string literals and constants are collected from method bodies
//! 2. Constants are encoded into a byte array with type tags:
//!    - Type 0: String (UTF-8 encoded, length-prefixed)
//!    - Type 1: Primitive value (int, long, float, double, etc.)
//!    - Type 2: Array of primitives
//! 3. The byte array is encrypted using XOR with a derived key
//! 4. The encrypted data is compressed with LZMA
//! 5. The compressed data is stored in a FieldRVA (static field with initialization data)
//!
//! ## Runtime Initialization
//!
//! **Source:** `Confuser.Runtime/Constant.cs`
//!
//! ```csharp
//! internal static class Constant {
//!     static byte[] b;  // Decrypted buffer
//!
//!     static void Initialize() {
//!         var l = (uint)Mutation.KeyI0;           // Length
//!         uint[] q = Mutation.Placeholder(...);   // Encrypted data
//!         var k = new uint[0x10];                 // Key (16 entries)
//!
//!         // XORShift32 key generation
//!         var n = (uint)Mutation.KeyI1;
//!         for (int i = 0; i < 0x10; i++) {
//!             n ^= n >> 12;
//!             n ^= n << 25;
//!             n ^= n >> 27;
//!             k[i] = n;
//!         }
//!
//!         // ... XOR decryption with Mutation.Crypt (DynCipher) ...
//!         b = Lzma.Decompress(o);
//!     }
//!
//!     static T Get<T>(int id) {
//!         // Type-dispatched constant retrieval
//!     }
//! }
//! ```
//!
//! # Call Site Replacement Modes
//!
//! ConfuserEx has two modes for replacing constant references with decryptor calls:
//!
//! ## Normal Mode (cfg=false, default)
//!
//! Simple stateless pattern - each call is independent:
//!
//! ```text
//! Original:    ldstr "Hello"
//! Obfuscated:  ldc.i4 0x12345678
//!              call Decryptor<string>
//! ```
//!
//! **Key encoding:** `encoded = (id ^ key.Item2) * key.Item1`
//! **Key decoding:** `id = (encoded * modInv(key.Item1)) ^ key.Item2`
//!
//! Each decryptor call is **independent** - no state dependency between calls.
//! This mode is simpler but provides less protection.
//!
//! ## CFG Mode (cfg=true)
//!
//! Control-flow-aware stateful pattern - calls are order-dependent:
//!
//! ```text
//! Original:    ldstr "Hello"
//! Obfuscated:  ldloca CFGCtx          ; State variable address
//!              ldc.i4.s FLAG          ; Update/get config byte
//!              ldc.i4 INCREMENT       ; State modification value
//!              call CFGCtx.Next       ; Returns state value & modifies state
//!              ldc.i4 ENCODED         ; Encoded constant
//!              xor                    ; actual_key = ENCODED ^ state_value
//!              call Decryptor         ; Uses actual_key
//! ```
//!
//! ### CFGCtx State Machine
//!
//! **Source:** `Confuser.Runtime/Constant.cs`
//!
//! ```csharp
//! internal struct CFGCtx {
//!     uint A, B, C, D;  // 4 state values
//!
//!     // Initialize from seed with multiplicative chain
//!     public CFGCtx(uint seed) {
//!         A = seed *= 0x21412321;
//!         B = seed *= 0x21412321;
//!         C = seed *= 0x21412321;
//!         D = seed *= 0x21412321;
//!     }
//!
//!     // Update state and return a value
//!     public uint Next(byte f, uint q) {
//!         // Update based on (f & 0x3):
//!         // Bit 7 (0x80): Explicit (1) vs Incremental (0)
//!         // If explicit: state[f & 0x3] = q
//!         // If incremental:
//!         //   - slot 0: A ^= q
//!         //   - slot 1: B += q
//!         //   - slot 2: C ^= q
//!         //   - slot 3: D -= q
//!
//!         // Return based on ((f >> 2) & 0x3):
//!         //   - 0: return A
//!         //   - 1: return B
//!         //   - 2: return C
//!         //   - 3: return D
//!     }
//! }
//! ```
//!
//! ### Flag Byte Encoding
//!
//! The `flag` parameter to `CFGCtx.Next()` encodes:
//! - **Bit 7 (0x80)**: Update mode - Explicit (1) or Incremental (0)
//! - **Bits 0-1**: State slot to update (0=A, 1=B, 2=C, 3=D)
//! - **Bits 2-3**: State slot to return (0=A, 1=B, 2=C, 3=D)
//!
//! ### Order Dependency
//!
//! In CFG mode, decryptor calls **MUST be processed in execution order**:
//!
//! 1. State is initialized per basic block with a seed
//! 2. Each `CFGCtx.Next()` call modifies state AND returns a value
//! 3. The returned value is XORed with the encoded constant to get the actual key
//! 4. If calls are processed out of order, state values will be wrong
//!
//! ```text
//! Block entry:  CFGCtx(seed=0x12345678) → A=0x..., B=0x..., C=0x..., D=0x...
//! Call 1:       Next(flag1, val1) → modifies state, returns X1
//!               key1 = encoded1 ^ X1
//! Call 2:       Next(flag2, val2) → modifies state, returns X2
//!               key2 = encoded2 ^ X2
//! ...
//! ```
//!
//! # Cipher Modes (Initialize method)
//!
//! The Initialize method's decryption can use different cipher modes:
//!
//! ## Normal Cipher (mode=Normal, default)
//!
//! Uses static XOR encryption with compile-time keys in the Initialize method.
//! The XORShift32 constants (12, 25, 27) are embedded as literal instructions.
//!
//! ## Dynamic Cipher (mode=Dynamic)
//!
//! Uses `Mutation.Crypt()` which is a dynamically-generated cipher.
//! Each protected assembly gets a unique cipher derived at compile time.
//! The cipher operates on 16-entry uint arrays in a CBC-like mode.
//!
//! ## x86 Cipher (mode=x86)
//!
//! Uses native x86 code for key derivation (Windows-only).
//! Creates methods with `MethodImplCodeType::NATIVE` containing raw machine code.
//! Requires [`NativeMethodConversionPass`] before emulation.
//!
//! # Decryptor Signatures
//!
//! Typical signatures for the Get method:
//! - `static string(int32)` - Non-generic string decryptor
//! - `static T Get<T>(int32)` - Generic decryptor for any type
//!
//! The generic decryptor method `Get<T>(int id)` characteristics:
//! - Generic method with single type parameter
//! - Single `int32` parameter
//! - Returns `T`
//! - Calls `Assembly.GetExecutingAssembly()` and `Assembly.GetCallingAssembly()`
//! - Calls `Encoding.UTF8.GetString()` for strings
//! - Calls `string.Intern()` for string interning
//!
//! # Detection Strategy
//!
//! ## Decryptor Method Detection
//!
//! Look for methods matching these criteria:
//! 1. Located in `<Module>` type or obfuscated-name type
//! 2. Static method
//! 3. Signature: `string(int32)` or `T(int32)` generic
//! 4. Contains characteristic IL patterns (assembly checks, encoding calls)
//!
//! ## CFG Mode Detection
//!
//! Look for:
//! 1. Local variable with CFGCtx-like initialization (`* 0x21412321` pattern)
//! 2. `ldloca; ldc.i4.s; ldc.i4; call; ... xor; call` instruction sequences
//! 3. Multiple decryptor calls with preceding XOR operations
//!
//! ## Call Site Detection
//!
//! ### Normal Mode Call Sites
//!
//! Pattern: `ldc.i4 KEY; call Decryptor`
//!
//! The instruction immediately before the call loads the constant key.
//! This key can be directly used for emulation.
//!
//! ### CFG Mode Call Sites
//!
//! Pattern:
//! ```text
//! ldloca CFGCtx
//! ldc.i4.s FLAG
//! ldc.i4 INCREMENT
//! call CFGCtx.Next    ← Returns XOR operand
//! ldc.i4 ENCODED      ← Encoded value
//! xor                 ← Compute actual key
//! call Decryptor      ← Use computed key
//! ```
//!
//! For CFG mode, we cannot simply look at the instruction before the call.
//! We must either:
//! 1. Simulate the CFGCtx state machine
//! 2. Use backward slicing to find all inputs to the XOR
//! 3. Emulate the key computation path
//!
//! # Decryption Strategy
//!
//! ## For Normal Mode
//!
//! 1. Find call sites with `ldc.i4 KEY; call Decryptor` pattern
//! 2. Extract the KEY value directly from the preceding instruction
//! 3. Emulate the decryptor with the KEY argument
//! 4. Replace the call sequence with the decrypted constant
//!
//! ## For CFG Mode
//!
//! 1. Detect CFGCtx usage in the method (local variable with specific init)
//! 2. Build control flow graph
//! 3. For each basic block:
//!    a. Initialize CFGCtx state (from seed or predecessor state)
//!    b. Process decryptor call sites in execution order
//!    c. Simulate CFGCtx.Next() to compute actual keys
//!    d. Emulate decryptor with computed keys
//!    e. Track state transitions to successor blocks
//! 4. Replace call sequences with decrypted constants
//!
//! # Integration with SSA Passes
//!
//! String/constant decryption happens during SSA-level passes:
//! 1. The decryption pass identifies calls to decryptor methods
//! 2. For Normal mode: extract key from preceding instruction
//! 3. For CFG mode: use SSA def-use chains to trace key computation
//! 4. Emulate the decryptor with the resolved key
//! 5. Replace the call with a constant in SSA form
//!
//! Decryptor methods are identified during detection and stored in
//! [`ConfuserExFindings::decryptor_methods`](super::ConfuserExFindings::decryptor_methods).
//!
//! # Test Samples
//!
//! | Sample | Has Constants | Mode | CFG | Notes |
//! |--------|---------------|------|-----|-------|
//! | `original.exe` | No | N/A | N/A | Unprotected baseline |
//! | `mkaring_minimal.exe` | No | N/A | N/A | Minimum preset |
//! | `mkaring_normal.exe` | Yes | Normal | No | Normal preset |
//! | `mkaring_constants.exe` | Yes | Normal | No | Constants-only |
//! | `mkaring_constants_dyncyph.exe` | Yes | Dynamic | No | mode=dynamic |
//! | `mkaring_constants_cfg.exe` | Yes | Dynamic | Yes | cfg=true, state machine |
//! | `mkaring_constants_x86.exe` | Yes | x86 | No | mode=x86, native code |
//! | `mkaring_maximum.exe` | Yes | Dynamic | ? | Maximum preset |
//!
//! # Current Implementation Status
//!
//! ## Supported
//!
//! - Decryptor method detection (both signatures)
//! - Normal mode call site detection (`ldc.i4; call` pattern)
//! - CFG mode call site detection (`xor; call` pattern)
//! - Initialize method discovery for warmup
//! - MethodSpec → MethodDef mapping for generic instantiations
//! - CFGCtx state machine semantic extraction
//!
//! ## Not Yet Supported
//!
//! - Backward slicing for complex key computation
//! - x86 cipher mode (requires native code conversion first)

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use dashmap::DashSet;

use crate::{
    analysis::{
        ConstValue, PhiTaintMode, SsaFunction, SsaOp, SsaVarId, TaintAnalysis, TaintConfig,
    },
    assembly::Operand,
    compiler::CompilerContext,
    deobfuscation::{
        detection::{DetectionEvidence, DetectionScore},
        obfuscators::confuserex::findings::ConfuserExFindings,
        CfgInfo, StateMachineCallSite, StateMachineProvider, StateMachineSemantics,
        StateSlotOperation, StateUpdateCall,
    },
    metadata::{
        method::MethodModifiers,
        signatures::TypeSignature,
        tables::TableId,
        token::Token,
        typesystem::{CilFlavor, CilType},
    },
    prelude::FlowType,
    utils::graph::NodeId,
    CilObject,
};

/// Internal: Information about a call site to a decryptor method.
struct DetectedCallSite {
    /// Method containing the call.
    caller: Token,
    /// Whether this call uses state machine mode.
    uses_statemachine: bool,
}

impl DetectedCallSite {
    /// Creates a new call site with direct mode.
    fn direct(caller: Token) -> Self {
        Self {
            caller,
            uses_statemachine: false,
        }
    }

    /// Creates a new call site with state machine mode.
    fn statemachine(caller: Token) -> Self {
        Self {
            caller,
            uses_statemachine: true,
        }
    }
}

/// ConfuserEx state machine provider for CFG mode constant decryption.
///
/// This implements the [`StateMachineProvider`] trait for ConfuserEx's CFGCtx
/// state machine. It encapsulates:
/// - The detected semantics (multiplier, slot operations)
/// - The set of methods that use CFG mode
/// - Methods to find initializations and state updates in SSA
///
/// # Usage
///
/// Created during ConfuserEx detection when CFG mode is detected:
/// ```rust,ignore
/// let provider = ConfuserExStateMachine::new(semantics, methods);
/// ctx.register_statemachine_provider(Arc::new(provider));
/// ```
#[derive(Debug)]
pub struct ConfuserExStateMachine {
    /// The detected CFGCtx semantics.
    semantics: StateMachineSemantics,
    /// Methods that use this state machine for encryption.
    methods: DashSet<Token>,
}

impl ConfuserExStateMachine {
    /// Creates a new ConfuserEx state machine provider.
    ///
    /// # Arguments
    ///
    /// * `semantics` - The detected CFGCtx semantics.
    /// * `methods` - Iterator of method tokens that use CFG mode.
    pub fn new(semantics: StateMachineSemantics, methods: impl IntoIterator<Item = Token>) -> Self {
        let method_set = DashSet::new();
        for method in methods {
            method_set.insert(method);
        }
        Self {
            semantics,
            methods: method_set,
        }
    }
}

impl StateMachineProvider for ConfuserExStateMachine {
    fn name(&self) -> &'static str {
        "ConfuserEx CFGCtx"
    }

    fn semantics(&self) -> &StateMachineSemantics {
        &self.semantics
    }

    fn applies_to_method(&self, method: Token) -> bool {
        self.methods.contains(&method)
    }

    fn methods(&self) -> Vec<Token> {
        self.methods.iter().map(|r| *r).collect()
    }

    fn find_initializations(
        &self,
        ssa: &SsaFunction,
        ctx: &CompilerContext,
        method_token: Token,
        _assembly: &Arc<CilObject>,
    ) -> Vec<(usize, usize, u32)> {
        let mut seeds = Vec::new();

        let Some(init_method_token) = self.semantics.init_method else {
            return seeds;
        };

        // Look for all calls to the CFGCtx constructor
        for (block_idx, block) in ssa.iter_blocks() {
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                match instr.op() {
                    // Value type initialization uses Call to .ctor
                    SsaOp::Call { method, args, .. } if method.token() == init_method_token => {
                        // .ctor for value type: args are (&this, seed)
                        if args.len() >= 2 {
                            let seed_var = args[1];
                            if let Some(ConstValue::I32(seed)) =
                                self.trace_to_constant(seed_var, ssa, ctx, method_token)
                            {
                                #[allow(clippy::cast_sign_loss)]
                                seeds.push((block_idx, instr_idx, seed as u32));
                            }
                        }
                    }
                    // NewObj for reference types (less common for CFGCtx)
                    SsaOp::NewObj { ctor, args, .. } if ctor.token() == init_method_token => {
                        if args.len() == 1 {
                            if let Some(ConstValue::I32(seed)) =
                                self.trace_to_constant(args[0], ssa, ctx, method_token)
                            {
                                #[allow(clippy::cast_sign_loss)]
                                seeds.push((block_idx, instr_idx, seed as u32));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        seeds
    }

    fn find_state_updates(&self, ssa: &SsaFunction) -> Vec<StateUpdateCall> {
        let mut updates = Vec::new();

        let Some(update_method_token) = self.semantics.update_method else {
            return updates;
        };

        for (block_idx, block) in ssa.iter_blocks() {
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                if let SsaOp::Call { method, args, dest } | SsaOp::CallVirt { method, args, dest } =
                    instr.op()
                {
                    if method.token() == update_method_token {
                        // CFGCtx.Next takes 3 args: &this, flag (byte), increment (uint)
                        if args.len() >= 3 {
                            if let Some(dest) = dest {
                                updates.push(StateUpdateCall {
                                    block_idx,
                                    instr_idx,
                                    dest: *dest,
                                    flag_var: args[1],
                                    increment_var: args[2],
                                });
                            }
                        }
                    }
                }
            }
        }

        updates
    }

    fn find_decryptor_call_sites(
        &self,
        ssa: &SsaFunction,
        state_updates: &[StateUpdateCall],
        decryptor_tokens: &HashSet<Token>,
        assembly: &Arc<CilObject>,
    ) -> Vec<StateMachineCallSite> {
        let mut call_sites = Vec::new();

        // Build a map from Next() result var -> StateUpdateCall index
        let mut next_info_map: HashMap<SsaVarId, usize> = HashMap::new();
        for (idx, update) in state_updates.iter().enumerate() {
            next_info_map.insert(update.dest, idx);
        }

        // Find decryptor calls that use XOR results
        for (block_idx, block) in ssa.iter_blocks() {
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                let (call_target, args, dest) = match instr.op() {
                    SsaOp::Call { method, args, dest } | SsaOp::CallVirt { method, args, dest } => {
                        (method.token(), args, *dest)
                    }
                    _ => continue,
                };

                let Some(dest) = dest else { continue };

                // Resolve MethodSpec to MethodDef for generic method calls
                // Generic decryptors like T Get<T>(int32) are called via MethodSpec tokens
                let resolved_target =
                    resolve_method_spec_to_def(assembly, call_target).unwrap_or(call_target);

                // Check if this is a decryptor call
                if !decryptor_tokens.contains(&resolved_target) {
                    continue;
                }

                if args.len() != 1 {
                    continue;
                }

                // Check if argument comes from XOR
                let Some(SsaOp::Xor { left, right, .. }) = ssa.get_definition(args[0]) else {
                    continue;
                };

                // Determine which XOR operand is from state update (CFGCtx.Next())
                let (state_var, encoded_var, feeding_idx) =
                    if let Some(&idx) = next_info_map.get(left) {
                        (*left, *right, idx)
                    } else if let Some(&idx) = next_info_map.get(right) {
                        (*right, *left, idx)
                    } else {
                        continue;
                    };

                call_sites.push(StateMachineCallSite {
                    block_idx,
                    instr_idx,
                    dest,
                    decryptor: resolved_target,
                    state_var,
                    encoded_var,
                    feeding_update_idx: feeding_idx,
                });
            }
        }

        call_sites
    }

    fn collect_updates_for_call(
        &self,
        call_site: &StateMachineCallSite,
        all_updates: &[StateUpdateCall],
        cfg_info: &CfgInfo<'_>,
    ) -> Vec<usize> {
        let feeding_update = &all_updates[call_site.feeding_update_idx];

        // Group state update calls by block for efficient lookup
        let mut updates_by_block: HashMap<usize, Vec<usize>> = HashMap::new();
        for (idx, update) in all_updates.iter().enumerate() {
            updates_by_block
                .entry(update.block_idx)
                .or_default()
                .push(idx);
        }

        // Sort each block's updates by instruction index
        for indices in updates_by_block.values_mut() {
            indices.sort_by_key(|&idx| all_updates[idx].instr_idx);
        }

        // Collect state updates that are GUARANTEED to execute before the feeding update:
        // 1. All updates in blocks that DOMINATE the feeding update's block
        // 2. Updates in the SAME block that come BEFORE the feeding update
        let mut relevant_updates: Vec<usize> = Vec::new();

        for (block_idx, update_indices) in &updates_by_block {
            // Skip blocks that are out of bounds
            if *block_idx >= cfg_info.node_count || feeding_update.block_idx >= cfg_info.node_count
            {
                continue;
            }

            if *block_idx == feeding_update.block_idx {
                // Same block - include only updates BEFORE the feeding one
                for &idx in update_indices {
                    if all_updates[idx].instr_idx < feeding_update.instr_idx {
                        relevant_updates.push(idx);
                    }
                }
            } else if cfg_info.dom_tree.strictly_dominates(
                NodeId::new(*block_idx),
                NodeId::new(feeding_update.block_idx),
            ) {
                // This block dominates the feeding update's block - include ALL its updates
                relevant_updates.extend(update_indices.iter().copied());
            }
        }

        // FALLBACK for merge blocks: if no dominating updates found and the block
        // has multiple predecessors, trace back through predecessors to find a path.
        if relevant_updates.is_empty() && feeding_update.block_idx < cfg_info.predecessors.len() {
            let block_preds = &cfg_info.predecessors[feeding_update.block_idx];
            if block_preds.len() > 1 {
                // Merge block with multiple predecessors - trace back through ONE path
                let mut best_path: Vec<usize> = Vec::new();

                for &pred in block_preds {
                    let mut path_updates: Vec<usize> = Vec::new();
                    let mut current = pred;
                    let mut visited: HashSet<usize> = HashSet::new();

                    // Trace back from predecessor to entry, collecting updates
                    while current != cfg_info.entry.index() && visited.insert(current) {
                        if let Some(indices) = updates_by_block.get(&current) {
                            path_updates.extend(indices.iter().copied());
                        }

                        // Move to the immediate dominator (guaranteed path to entry)
                        if current < cfg_info.node_count
                            && cfg_info
                                .dom_tree
                                .dominates(cfg_info.entry, NodeId::new(current))
                        {
                            if let Some(idom) =
                                cfg_info.dom_tree.immediate_dominator(NodeId::new(current))
                            {
                                current = idom.index();
                            } else {
                                break;
                            }
                        } else {
                            break;
                        }
                    }

                    // Prefer paths with more updates (more likely to be the "full" path)
                    if path_updates.len() > best_path.len() {
                        best_path = path_updates;
                    }
                }

                relevant_updates = best_path;
            }
        }

        // Sort relevant updates by execution order (dominator depth, then block, then instruction)
        relevant_updates.sort_by_key(|&idx| {
            let update = &all_updates[idx];
            let depth = if update.block_idx < cfg_info.node_count
                && cfg_info
                    .dom_tree
                    .dominates(cfg_info.entry, NodeId::new(update.block_idx))
            {
                cfg_info.dom_tree.depth(NodeId::new(update.block_idx))
            } else {
                usize::MAX // Unreachable - sort last
            };
            (depth, update.block_idx, update.instr_idx)
        });

        relevant_updates
    }
}

/// Detects constants encryption patterns and populates findings.
///
/// This performs complete detection of ConfuserEx constants protection including:
/// 1. Finding decryptor methods (signatures: `string(int32)` or `T(int32)`)
/// 2. Detecting CFG mode usage via SSA dataflow analysis
/// 3. Extracting state machine semantics (multiplier, slot operations)
///
/// CFG mode is identified when the decryptor call argument traces back to an XOR
/// operation (one operand constant, one from CFGCtx.Next() state machine).
pub fn detect(assembly: &CilObject, score: &DetectionScore, findings: &mut ConfuserExFindings) {
    let decryptors = find_decryptor_methods(assembly);
    if decryptors.is_empty() {
        return;
    }

    // Populate findings with decryptor methods (single iteration)
    for token in &decryptors {
        findings.decryptor_methods.push(*token);
    }

    // Add detection evidence for decryptors
    let decryptor_confidence = (decryptors.len() * 20).min(30);
    score.add(DetectionEvidence::MetadataPattern {
        name: format!(
            "Constant decryptor methods ({} with signature string(int32) or T(int32))",
            decryptors.len()
        ),
        locations: decryptors.iter().copied().collect(),
        confidence: decryptor_confidence,
    });

    // Detect CFG mode using SSA-based dataflow analysis
    // This properly traces the call argument through XOR operations
    let call_sites = find_call_sites(assembly, &decryptors);

    // Collect unique methods that use CFG mode (state machine decryption)
    let cfg_mode_methods: HashSet<Token> = call_sites
        .iter()
        .filter(|site| site.uses_statemachine)
        .map(|site| site.caller)
        .collect();

    // If CFG mode patterns found, extract state machine semantics and create provider
    if !cfg_mode_methods.is_empty() {
        if let Some(semantics) = detect_cfgctx_semantics(assembly) {
            #[allow(clippy::cast_possible_truncation)]
            let multiplier = semantics.init_constant.unwrap_or(0) as u32;
            let method_count = cfg_mode_methods.len();

            // Create the state machine provider
            let provider = ConfuserExStateMachine::new(semantics, cfg_mode_methods.iter().copied());
            findings.statemachine_provider = Some(Arc::new(provider));

            let cfg_confidence = (method_count * 15).min(25);
            score.add(DetectionEvidence::BytecodePattern {
                name: format!(
                    "CFG mode constant encryption ({} methods, multiplier=0x{:08X})",
                    method_count, multiplier
                ),
                locations: cfg_mode_methods.into_iter().collect(),
                confidence: cfg_confidence,
            });
        }
    }
}

/// Detects CFGCtx state machine semantics from the assembly.
///
/// This function fully analyzes the CFGCtx value type to extract:
/// - The type token
/// - The constructor and its multiplier
/// - The Next method and its slot operations
///
/// # CFGCtx Structure
///
/// ```text
/// internal struct CFGCtx {
///     uint A, B, C, D;
///
///     public CFGCtx(uint seed) {
///         A = seed *= MULTIPLIER;
///         B = seed *= MULTIPLIER;
///         C = seed *= MULTIPLIER;
///         D = seed *= MULTIPLIER;
///     }
///
///     public uint Next(byte flag, uint value) {
///         switch (flag & 3) {
///             case 0: if (flag & 0x80) A = value; else A ^= value; break;
///             case 1: if (flag & 0x80) B = value; else B += value; break;
///             case 2: if (flag & 0x80) C = value; else C ^= value; break;
///             case 3: if (flag & 0x80) D = value; else D -= value; break;
///         }
///         return (flag >> 2 & 3) switch { 0 => A, 1 => B, 2 => C, 3 => D };
///     }
/// }
/// ```
fn detect_cfgctx_semantics(assembly: &CilObject) -> Option<StateMachineSemantics> {
    // First, try nested types inside <Module> (ConfuserEx sometimes nests CFGCtx there)
    if let Some(module_type) = assembly.types().module_type() {
        for (_, nested_ref) in module_type.nested_types.iter() {
            let nested_type = nested_ref.upgrade()?;
            if let Some(semantics) = try_detect_cfgctx_from_type(assembly, &nested_type) {
                return Some(semantics);
            }
        }
    }

    // If not found in <Module>, scan all top-level types in the assembly
    // ConfuserEx can inject CFGCtx as a top-level type
    for type_entry in assembly.types().iter() {
        let cil_type = type_entry.value();

        // Skip types with ASCII names (CFGCtx has obfuscated names)
        if cil_type.name.is_ascii() && !cil_type.name.is_empty() {
            continue;
        }

        // Check if this type could be CFGCtx
        if let Some(semantics) = try_detect_cfgctx_from_type(assembly, cil_type) {
            return Some(semantics);
        }
    }

    None
}

/// Attempts to detect CFGCtx from a type definition.
///
/// CFGCtx characteristics:
/// - Value type (struct) with exactly 4 fields (A, B, C, D)
/// - Constructor with multiplicative chain initialization
/// - Next method with signature (byte, uint) -> uint
fn try_detect_cfgctx_from_type(
    assembly: &CilObject,
    cil_type: &CilType,
) -> Option<StateMachineSemantics> {
    // CFGCtx is a value type (struct) with uint fields
    if *cil_type.flavor() != CilFlavor::ValueType {
        return None;
    }

    // Must have exactly 4 fields (A, B, C, D)
    if cil_type.fields.count() != 4 {
        return None;
    }

    // Look for constructor and Next method
    let mut ctor_token: Option<Token> = None;
    let mut next_token: Option<Token> = None;
    let mut multiplier: Option<u32> = None;

    for (_, method_ref) in cil_type.methods.iter() {
        let method = method_ref.upgrade()?;

        if method.is_ctor() && ctor_token.is_none() {
            // Found constructor - extract multiplier using SSA dataflow analysis
            if let Some(ssa) = method.ssa(assembly) {
                if let Some(mult) = extract_multiplier_from_ssa(&ssa) {
                    multiplier = Some(mult);
                    ctor_token = Some(method.token);
                }
            }
        } else if next_token.is_none() {
            // Check for Next-like method - may have obfuscated name
            // Look for signature with 2 params (byte, uint) that returns uint
            let sig = &method.signature;
            if sig.params.len() == 2 && method.name != ".ctor" {
                // Use SSA to look for characteristic patterns (switch, field stores/loads)
                if let Some(ssa) = method.ssa(assembly) {
                    let mut has_switch = false;
                    let mut has_stfld = false;
                    let mut has_ldfld = false;

                    for (_, block) in ssa.iter_blocks() {
                        for instr in block.instructions().iter() {
                            match instr.op() {
                                SsaOp::Switch { .. } => has_switch = true,
                                SsaOp::StoreField { .. } => has_stfld = true,
                                SsaOp::LoadField { .. } => has_ldfld = true,
                                _ => {}
                            }
                        }
                    }

                    if has_switch && has_stfld && has_ldfld {
                        next_token = Some(method.token);
                    }
                }
            }
        }
    }

    // Need both ctor (with multiplier) and Next method
    let (Some(init_method), Some(update_method), Some(mult)) = (ctor_token, next_token, multiplier)
    else {
        return None;
    };

    // Collect field tokens in order (for mapping stfld targets to slot indices)
    let field_tokens: Vec<Token> = (0..cil_type.fields.count())
        .filter_map(|i| cil_type.fields.get(i))
        .map(|f| f.token)
        .collect();

    // Extract slot operations from the Next method by analyzing its IL
    // This must succeed for CFGCtx to be usable
    let slot_ops = extract_slot_operations(assembly, update_method, &field_tokens)?;

    Some(StateMachineSemantics {
        type_token: Some(cil_type.token),
        init_method: Some(init_method),
        update_method: Some(update_method),
        slot_count: 4,
        slot_ops,
        init_ops: vec![
            StateSlotOperation::mul(),
            StateSlotOperation::mul(),
            StateSlotOperation::mul(),
            StateSlotOperation::mul(),
        ],
        init_constant: Some(u64::from(mult)),
        explicit_flag_bit: 7,
        update_slot_mask: 0x03,
        get_slot_mask: 0x03,
        get_slot_shift: 2,
    })
}

/// Extracts the multiplier constant from a CFGCtx constructor using SSA analysis.
///
/// The constructor initializes fields with a multiplicative chain:
/// ```text
/// A = seed *= MULTIPLIER
/// B = seed *= MULTIPLIER
/// C = seed *= MULTIPLIER
/// D = seed *= MULTIPLIER
/// ```
///
/// This function finds Mul operations and extracts the constant operand,
/// using SSA dataflow to handle CFF and other obfuscations.
fn extract_multiplier_from_ssa(ssa: &SsaFunction) -> Option<u32> {
    for (_, block) in ssa.iter_blocks() {
        for instr in block.instructions().iter() {
            // Look for Mul operations
            let (left, right) = match instr.op() {
                SsaOp::Mul { left, right, .. } | SsaOp::MulOvf { left, right, .. } => {
                    (*left, *right)
                }
                _ => continue,
            };

            // Check if either operand is a constant that looks like a multiplier
            for operand in [left, right] {
                if let Some(mult) = get_i32_constant(ssa, operand) {
                    // Filter out small constants (unlikely to be the multiplier)
                    // The ConfuserEx default is 0x21412321
                    if mult != 0 && mult.abs() > 0x1000 {
                        #[allow(clippy::cast_sign_loss)]
                        return Some(mult as u32);
                    }
                }
            }
        }
    }

    None
}

/// Extracts slot operations from the CFGCtx.Next method using SSA dataflow analysis.
///
/// The Next method has switch cases for each slot:
/// - Case 0: A ^= value (XOR)
/// - Case 1: B += value (ADD)
/// - Case 2: C ^= value (XOR)
/// - Case 3: D -= value (SUB)
///
/// This function uses SSA-based backward tracing from StoreField operations to find
/// the arithmetic operation that produces the stored value. This is robust against
/// control flow flattening because SSA captures data dependencies, not instruction order.
///
/// # Arguments
///
/// * `assembly` - The assembly containing the method.
/// * `next_method` - Token of the Next method.
/// * `field_tokens` - Tokens of the type's fields in order (for mapping stfld targets to slot indices).
///
/// Returns `None` if the slot operations cannot be determined from the SSA.
fn extract_slot_operations(
    assembly: &CilObject,
    next_method: Token,
    field_tokens: &[Token],
) -> Option<Vec<StateSlotOperation>> {
    let method_entry = assembly.methods().get(&next_method)?;
    let method = method_entry.value();

    // Build SSA for the method - this gives us proper data flow analysis
    let ssa = method.ssa(assembly)?;

    let mut ops_found: Vec<(usize, StateSlotOperation)> = Vec::new();

    // Find all StoreField operations and trace backward to find the arithmetic op
    for (_, block) in ssa.iter_blocks() {
        for instr in block.instructions().iter() {
            // Look for StoreField (stfld) operations
            let (field_token, value_var) = match instr.op() {
                SsaOp::StoreField { field, value, .. } => (field.token(), *value),
                _ => continue,
            };

            // Map field to slot index
            let Some(slot_idx) = field_tokens.iter().position(|t| *t == field_token) else {
                continue;
            };

            // Trace backward from the stored value to find the operation
            if let Some(slot_op) = trace_to_arithmetic_op(&ssa, value_var) {
                ops_found.push((slot_idx, slot_op));
            }
        }
    }

    // Sort by slot index and deduplicate (take first occurrence for each slot)
    ops_found.sort_by_key(|(idx, _)| *idx);
    ops_found.dedup_by_key(|(idx, _)| *idx);

    // Must have exactly 4 operations in order to be valid
    if ops_found.len() == 4 && ops_found.iter().enumerate().all(|(i, (idx, _))| *idx == i) {
        return Some(ops_found.into_iter().map(|(_, op)| op).collect());
    }

    // Detection failed - return None instead of using defaults
    None
}

/// Traces backward from an SSA variable to find the arithmetic operation that produces it.
///
/// Uses SSA def-use chains to find the operation, handling PHI nodes and
/// intermediate operations. This is CFF-resistant because it follows data flow,
/// not instruction order.
///
/// Uses an iterative worklist algorithm instead of recursion to avoid stack overflow
/// on deeply nested or cyclic graphs.
fn trace_to_arithmetic_op(ssa: &SsaFunction, start_var: SsaVarId) -> Option<StateSlotOperation> {
    // Worklist of variables to examine
    let mut worklist = vec![start_var];
    // Track visited variables to prevent infinite loops
    let mut visited: HashSet<SsaVarId> = HashSet::new();

    while let Some(var) = worklist.pop() {
        // Skip if already visited (handles cycles)
        if !visited.insert(var) {
            continue;
        }

        // Get the definition of this variable
        let Some(def) = ssa.get_definition(var) else {
            continue;
        };

        match def {
            // Direct arithmetic operations - found what we're looking for
            SsaOp::Xor { .. } => return Some(StateSlotOperation::xor()),
            SsaOp::Add { .. } | SsaOp::AddOvf { .. } => return Some(StateSlotOperation::add()),
            SsaOp::Sub { .. } | SsaOp::SubOvf { .. } => return Some(StateSlotOperation::sub()),
            SsaOp::Mul { .. } | SsaOp::MulOvf { .. } => return Some(StateSlotOperation::mul()),
            SsaOp::And { .. } => return Some(StateSlotOperation::and()),
            SsaOp::Or { .. } => return Some(StateSlotOperation::or()),

            // Conversion - add operand to worklist to trace through
            SsaOp::Conv { operand, .. } => {
                worklist.push(*operand);
            }

            // Other operations - check if this is a PHI result
            _ => {
                // Look for PHI nodes that define this variable
                for (_, block) in ssa.iter_blocks() {
                    for phi in block.phi_nodes().iter() {
                        if phi.result() == var {
                            // Add first operand to worklist
                            // (all operands should have same operation in well-formed CFGCtx)
                            if let Some(operand) = phi.operands().first() {
                                worklist.push(operand.value());
                            }
                        }
                    }
                }
            }
        }
    }

    None
}

/// Finds the constants Initialize() method that should be used for warmup.
///
/// ConfuserEx injects a separate `Initialize()` method into `<Module>` that performs
/// the expensive one-time initialization (LZMA decompression of the constants buffer).
/// This method is called from `.cctor`, but running the full `.cctor` also executes
/// anti-tamper/anti-debug code which can fail during emulation.
///
/// By finding and running `Initialize()` directly, we skip the protection code while
/// still initializing the decryptor state.
///
/// # Detection Criteria
///
/// The Initialize method:
/// 1. Is in `<Module>` type (same as decryptors)
/// 2. Is static void with no parameters
/// 3. Is called from `.cctor` (first instruction pattern)
/// 4. Contains LZMA-related patterns or stores to a byte[] field
///
/// # Arguments
///
/// * `assembly` - The assembly to search.
///
/// # Returns
///
/// Token of the Initialize method if found.
pub fn find_constants_initializer(assembly: &CilObject) -> Option<Token> {
    let module_type = assembly.types().module_type()?;

    // Get .cctor to find what methods it calls first
    let cctor_token = assembly.types().module_cctor()?;
    let cctor_entry = assembly.methods().get(&cctor_token)?;
    let cctor = cctor_entry.value();

    // Look at ALL call instructions in .cctor
    // ConfuserEx injects multiple calls: anti-tamper, constants, anti-debug, etc.
    let mut init_candidates: Vec<Token> = Vec::new();

    for instr in cctor.instructions() {
        if instr.flow_type == FlowType::Call {
            if let Operand::Token(call_target) = &instr.operand {
                // Check if this is a MethodDef (not MemberRef to external)
                if call_target.is_table(TableId::MethodDef) {
                    init_candidates.push(*call_target);
                }
            }
        }
    }

    // Now check each candidate to see if it matches Initialize() pattern
    for candidate in init_candidates {
        let Some(method_entry) = assembly.methods().get(&candidate) else {
            continue;
        };
        let method = method_entry.value();

        // Must be static
        if !method.is_static() {
            continue;
        }

        // Must be void with no parameters
        let sig = &method.signature;
        if sig.return_type.base != TypeSignature::Void || !sig.params.is_empty() {
            continue;
        }

        // Must be in <Module>
        let is_in_module = method
            .declaring_type
            .get()
            .and_then(|dt| dt.upgrade())
            .map(|t| t.name == "<Module>")
            .unwrap_or(false);

        if !is_in_module {
            continue;
        }

        // Check if it looks like an initializer:
        // - Contains ldsfld/stsfld to byte[] field
        // - Contains call to some decompression method
        // - Contains array allocation
        let mut has_array_ops = false;
        let mut has_field_store = false;

        for instr in method.instructions() {
            match instr.mnemonic {
                "newarr" | "newobj" => has_array_ops = true,
                "stsfld" => has_field_store = true,
                _ => {}
            }
        }

        // If it has array ops and stores to a static field, it's likely the initializer
        if has_array_ops && has_field_store {
            return Some(candidate);
        }
    }

    // Fallback: look for methods in <Module> that match the pattern without .cctor hint
    for (_, method_ref) in module_type.methods.iter() {
        let Some(method) = method_ref.upgrade() else {
            continue;
        };

        // Skip .cctor itself
        if method.is_cctor() {
            continue;
        }

        // Must be static void with no params
        if !method.flags_modifiers.contains(MethodModifiers::STATIC) {
            continue;
        }
        let sig = &method.signature;
        if sig.return_type.base != TypeSignature::Void || !sig.params.is_empty() {
            continue;
        }

        // Check for LZMA-related call pattern or Decompress in name
        for instr in method.instructions() {
            if instr.flow_type == FlowType::Call {
                if let Operand::Token(call_target) = &instr.operand {
                    // Check if calling a method with "Decompress" in name
                    if let Some(callee_entry) = assembly.methods().get(call_target) {
                        let callee = callee_entry.value();
                        if callee.name.contains("Decompress") || callee.name.contains("LZMA") {
                            return Some(method.token);
                        }
                    }
                    // Check MemberRef too
                    if let Some(memberref_entry) = assembly.refs_members().get(call_target) {
                        let memberref = memberref_entry.value();
                        if memberref.name.contains("Decompress") || memberref.name.contains("LZMA")
                        {
                            return Some(method.token);
                        }
                    }
                }
            }
        }
    }

    None
}

/// Finds all potential constants decryptor methods in the assembly.
///
/// Returns tokens of methods that match the decryptor signature pattern.
///
/// # Note
///
/// Prefer using `ConfuserExFindings::decryptor_methods` from detection results
/// instead of calling this function directly, to avoid redundant scanning.
pub fn find_decryptor_methods(assembly: &CilObject) -> Vec<Token> {
    let mut decryptors = Vec::new();

    for type_entry in assembly.types().iter() {
        let cil_type = type_entry.value();

        // ConfuserEx puts decryptors in <Module> or types with non-ASCII names
        let is_module_type = cil_type.name == "<Module>";
        let is_obfuscated_name = !cil_type.name.is_ascii();

        if !is_module_type && !is_obfuscated_name {
            continue;
        }

        for i in 0..cil_type.methods.count() {
            let Some(method_ref) = cil_type.methods.get(i) else {
                continue;
            };
            let Some(method) = method_ref.upgrade() else {
                continue;
            };

            // Must be static
            if !method.is_static() {
                continue;
            }

            let sig = &method.signature;

            // Check for string(int32) signature
            let is_string_decryptor = sig.param_count_generic == 0
                && sig.return_type.base == TypeSignature::String
                && sig.params.len() == 1
                && sig.params[0].base == TypeSignature::I4;

            // Check for generic T(int32) signature
            let is_generic_decryptor = sig.param_count_generic == 1
                && matches!(sig.return_type.base, TypeSignature::GenericParamMethod(0))
                && sig.params.len() == 1
                && sig.params[0].base == TypeSignature::I4;

            if is_string_decryptor || is_generic_decryptor {
                decryptors.push(method.token);
            }
        }
    }

    decryptors
}

/// Resolves a MethodSpec token to its underlying MethodDef token.
///
/// MethodSpec tokens (table 0x2B) are used for generic method instantiations.
/// This function extracts the underlying MethodDef token for comparison.
///
/// Returns `None` if the token is not a MethodSpec or if the underlying
/// method is a MemberRef (external method).
fn resolve_method_spec_to_def(assembly: &CilObject, token: Token) -> Option<Token> {
    if token.table() != 0x2B {
        return None; // Not a MethodSpec
    }

    let method_spec = assembly.method_specs().get(&token)?;
    let method_spec = method_spec.value();
    let method_token = method_spec.method.token()?;

    // Only return if it's a MethodDef (0x06), not a MemberRef
    if method_token.is_table(TableId::MethodDef) {
        Some(method_token)
    } else {
        None
    }
}

/// Finds all call sites to the specified decryptor methods using SSA dataflow analysis.
///
/// Uses proper SSA-based backward tracing to find argument values, handling:
/// - Direct constants (Normal mode)
/// - XOR results where one operand is a constant (CFG mode)
/// - Values traced through PHI nodes and other operations
///
/// # Normal Mode
///
/// Argument is a direct constant:
/// ```text
/// v1 = const KEY
/// v2 = call Decryptor(v1)
/// ```
///
/// # CFG Mode
///
/// Argument is computed via XOR with state machine value:
/// ```text
/// v1 = call CFGCtx.Next(...)   ; state_value
/// v2 = const ENCODED
/// v3 = xor v1, v2              ; or xor v2, v1
/// v4 = call Decryptor(v3)
/// ```
///
/// # Returns
///
/// A vector of detected call sites. Each site indicates the caller method
/// and whether it uses state machine mode.
fn find_call_sites(assembly: &CilObject, decryptor_tokens: &[Token]) -> Vec<DetectedCallSite> {
    let decryptor_set: HashSet<_> = decryptor_tokens.iter().copied().collect();
    let call_sites: boxcar::Vec<DetectedCallSite> = boxcar::Vec::new();

    for method_entry in assembly.methods().iter() {
        let method = method_entry.value();

        // Skip the decryptor methods themselves
        if decryptor_set.contains(&method.token) {
            continue;
        }

        // Build SSA for the method
        let Some(ssa) = method.ssa(assembly) else {
            continue;
        };

        // Find call instructions to decryptors
        for (_, block) in ssa.iter_blocks() {
            for instr in block.instructions().iter() {
                // Look for Call/CallVirt to decryptors
                let (call_target, args) = match instr.op() {
                    SsaOp::Call {
                        method: m, args, ..
                    }
                    | SsaOp::CallVirt {
                        method: m, args, ..
                    } => (m.token(), args),
                    _ => continue,
                };

                // Resolve MethodSpec to MethodDef if needed (for generic method calls)
                let resolved_target =
                    resolve_method_spec_to_def(assembly, call_target).unwrap_or(call_target);

                if !decryptor_set.contains(&resolved_target) {
                    continue;
                }

                // Decryptors take a single int32 argument
                if args.is_empty() {
                    continue;
                }

                let arg_var = args[0];

                // Use backward taint analysis to trace the argument's data flow
                match analyze_argument_dataflow(&ssa, arg_var) {
                    ArgumentAnalysis::DirectConstant(_) => {
                        // Normal mode: direct constant key
                        call_sites.push(DetectedCallSite::direct(method.token));
                    }
                    ArgumentAnalysis::XorWithConstant(_) => {
                        // CFG mode pattern: XOR with constant (no call in slice)
                        call_sites.push(DetectedCallSite::statemachine(method.token));
                    }
                    ArgumentAnalysis::FlowsThroughCall { constant } => {
                        // CFG mode: value depends on call result (likely CFGCtx.Next)
                        if constant.is_some() {
                            call_sites.push(DetectedCallSite::statemachine(method.token));
                        }
                        // If no constant found, we can't classify
                    }
                    ArgumentAnalysis::Unknown => {
                        // Cannot determine mode statically - assume direct
                        call_sites.push(DetectedCallSite::direct(method.token));
                    }
                }
            }
        }
    }

    call_sites.into_iter().collect()
}

/// Result of analyzing a decryptor call argument using backward taint analysis.
enum ArgumentAnalysis {
    /// Direct constant value (Normal mode) - the actual decryption key.
    DirectConstant(i32),
    /// Value computed via XOR with a constant (CFG mode).
    /// Contains the constant operand; actual key = constant ^ state_machine_output.
    XorWithConstant(i32),
    /// Value flows through a call (potentially CFGCtx.Next or other method).
    /// Contains the constant operand if found in the data flow.
    FlowsThroughCall { constant: Option<i32> },
    /// Cannot determine the value statically.
    Unknown,
}

/// Analyzes a decryptor call argument using backward taint analysis.
///
/// This uses proper SSA-based dataflow analysis to trace all operations
/// contributing to the argument value, regardless of instruction ordering.
/// This is robust against control flow flattening and other obfuscations.
///
/// # Analysis Strategy
///
/// 1. Start with the argument variable as taint source
/// 2. Propagate backward through def-use chains
/// 3. Collect all operations in the backward slice
/// 4. Classify based on what operations are found:
///    - Only constants → Normal mode (direct key)
///    - XOR with one constant operand → CFG mode (encoded key)
///    - Call instruction in the slice → state machine dependency
fn analyze_argument_dataflow(ssa: &SsaFunction, arg_var: SsaVarId) -> ArgumentAnalysis {
    // Quick check: if it's already a constant, we're done
    if let Some(key) = get_i32_constant(ssa, arg_var) {
        return ArgumentAnalysis::DirectConstant(key);
    }

    // Set up backward taint analysis
    let config = TaintConfig {
        forward: false,
        backward: true,
        phi_mode: PhiTaintMode::TaintAllOperands,
        max_iterations: 50,
    };

    let mut taint = TaintAnalysis::new(config);
    taint.add_tainted_var(arg_var);
    taint.propagate(ssa);

    // Collect all tainted operations for analysis
    let mut has_xor_with_const = None;
    let mut has_call = false;
    let mut call_const = None;

    // Examine all tainted variables and their definitions
    for var in taint.tainted_variables() {
        let Some(def) = ssa.get_definition(*var) else {
            continue;
        };

        match def {
            // Found an XOR - check if one operand is a constant
            SsaOp::Xor { left, right, .. } => {
                if let Some(c) = get_i32_constant(ssa, *left) {
                    has_xor_with_const = Some(c);
                } else if let Some(c) = get_i32_constant(ssa, *right) {
                    has_xor_with_const = Some(c);
                }
            }

            // Found a call - this indicates state machine or other method dependency
            SsaOp::Call { .. } | SsaOp::CallVirt { .. } => {
                has_call = true;
                // If we already found a constant in an XOR, preserve it
                if has_xor_with_const.is_some() {
                    call_const = has_xor_with_const;
                }
            }

            _ => {}
        }
    }

    // Classify based on what we found
    if has_call {
        // CFG mode: value depends on a call result (likely CFGCtx.Next)
        ArgumentAnalysis::FlowsThroughCall {
            constant: call_const.or(has_xor_with_const),
        }
    } else if let Some(constant) = has_xor_with_const {
        // XOR with constant but no call - still CFG-like pattern
        ArgumentAnalysis::XorWithConstant(constant)
    } else {
        ArgumentAnalysis::Unknown
    }
}

/// Gets the i32-equivalent constant value of an SSA variable.
///
/// Strategy for maximum coverage:
/// 1. `as_i32()` - handles I8, I16, I32, U8, U16, bool (including negative values)
/// 2. `as_u64()` + truncate - handles U32, U64, NativeUInt (positive values only)
fn get_i32_constant(ssa: &SsaFunction, var: SsaVarId) -> Option<i32> {
    let value = ssa
        .get_var_constant(var)
        .or_else(|| match ssa.get_definition(var) {
            Some(SsaOp::Const { value, .. }) => Some(value),
            _ => None,
        })?;

    // Try as_i32 first (handles signed types including negative values)
    // Then fall back to as_u64 + truncate (handles U32, U64, etc.)
    #[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
    value.as_i32().or_else(|| value.as_u64().map(|v| v as i32))
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, sync::Arc};

    use crate::{
        assembly::Operand,
        deobfuscation::{
            obfuscators::confuserex::constants::{
                detect_cfgctx_semantics, find_call_sites, find_decryptor_methods,
            },
            SsaOpKind, StateMachineSemantics, StateMachineState,
        },
        metadata::{tables::TableId, token::Token},
        prelude::FlowType,
        CilObject, ValidationConfig,
    };

    #[test]
    fn test_state_machine_from_seed() {
        // Test that our state machine implementation matches ConfuserEx CFGCtx runtime
        let semantics = Arc::new(StateMachineSemantics::confuserex_default());
        let state = StateMachineState::from_seed_u32(0x12345678, semantics);

        // Verify the multiplicative chain (default multiplier is 0x21412321)
        const MULTIPLIER: u32 = 0x2141_2321;
        let mut seed = 0x1234_5678_u32;
        seed = seed.wrapping_mul(MULTIPLIER);
        assert_eq!(state.get_u32(0), seed); // Slot A
        seed = seed.wrapping_mul(MULTIPLIER);
        assert_eq!(state.get_u32(1), seed); // Slot B
        seed = seed.wrapping_mul(MULTIPLIER);
        assert_eq!(state.get_u32(2), seed); // Slot C
        seed = seed.wrapping_mul(MULTIPLIER);
        assert_eq!(state.get_u32(3), seed); // Slot D
    }

    #[test]
    fn test_state_machine_next_incremental() {
        let semantics = Arc::new(StateMachineSemantics::confuserex_default());
        let mut state = StateMachineState::from_seed_u32(0, semantics);
        state.set(0, 0x1000_0000);
        state.set(1, 0x2000_0000);
        state.set(2, 0x3000_0000);
        state.set(3, 0x4000_0000);

        // Incremental update slot 0 (A ^= value), get slot 1 (return B)
        // Flag: 0b00000100 = (1 << 2) | 0 = get=1, update=0
        let flag = 0b0000_0100;
        let result = state.next_u32(flag, 0x0000_1111);
        assert_eq!(state.get_u32(0), 0x1000_0000 ^ 0x0000_1111);
        assert_eq!(result, state.get_u32(1));

        // Incremental update slot 1 (B += value), get slot 2 (return C)
        // Flag: 0b00001001 = (2 << 2) | 1 = get=2, update=1
        let flag = 0b0000_1001;
        let result = state.next_u32(flag, 0x0000_2222);
        assert_eq!(state.get_u32(1), 0x2000_0000_u32.wrapping_add(0x0000_2222));
        assert_eq!(result, state.get_u32(2));
    }

    #[test]
    fn test_state_machine_next_explicit() {
        let semantics = Arc::new(StateMachineSemantics::confuserex_default());
        let mut state = StateMachineState::from_seed_u32(0, semantics);
        state.set(0, 0x1000_0000);

        // Explicit update slot 0 (A = value), get slot 0 (return A)
        // Flag: 0x80 | 0 = explicit, update=0, get=0
        let flag = 0x80;
        let result = state.next_u32(flag, 0xDEAD_BEEF);
        assert_eq!(state.get_u32(0), 0xDEAD_BEEF);
        assert_eq!(result, 0xDEAD_BEEF);
    }

    /// Tests Normal mode constants detection on `mkaring_constants.exe`.
    ///
    /// `mkaring_constants.exe` uses Normal mode (no CFG):
    /// - 5 decryptor methods with signature string(int32) or T(int32)
    /// - Simple `ldc.i4 KEY; call Decryptor` call pattern
    /// - NO CFGCtx state machine (no order dependency)
    ///
    /// This is the simplest ConfuserEx constants protection mode.
    #[test]
    fn test_mkaring_constants_detection() {
        let assembly = CilObject::from_path_with_validation(
            "tests/samples/packers/confuserex/mkaring_constants.exe",
            ValidationConfig::analysis(),
        )
        .expect("Failed to load mkaring_constants.exe");

        // Should find 5 decryptor methods (0x06000004-0x06000008)
        let decryptors = find_decryptor_methods(&assembly);
        assert_eq!(
            decryptors.len(),
            5,
            "mkaring_constants.exe should have 5 decryptor methods"
        );

        // Verify expected tokens
        let expected_tokens: Vec<u32> =
            vec![0x06000004, 0x06000005, 0x06000006, 0x06000007, 0x06000008];
        for expected in &expected_tokens {
            assert!(
                decryptors.iter().any(|t| t.value() == *expected),
                "Expected decryptor 0x{:08X} not found",
                expected
            );
        }

        // Verify each decryptor has exactly 1 parameter (int32)
        for token in &decryptors {
            let method_entry = assembly
                .methods()
                .get(token)
                .expect("Decryptor should exist");
            let method = method_entry.value();
            assert_eq!(
                method.signature.params.len(),
                1,
                "Decryptor {:?} should have exactly 1 parameter",
                token
            );
        }

        // Normal mode: NO CFGCtx should be detected
        let cfgctx = detect_cfgctx_semantics(&assembly);
        assert!(
            cfgctx.is_none(),
            "mkaring_constants.exe uses Normal mode - should NOT have CFGCtx"
        );
    }

    /// Tests Dynamic cipher mode detection on `mkaring_constants_dyncyph.exe`.
    ///
    /// `mkaring_constants_dyncyph.exe` uses mode=dynamic (DynCipher):
    /// - 5 generic decryptor methods with signature T(int32)
    /// - Uses dynamic cipher for key derivation in Initialize()
    /// - NO CFGCtx state machine (call sites are order-independent)
    ///
    /// Config: confuserex_constants_dyncyph.crproj with mode="dynamic"
    #[test]
    fn test_mkaring_constants_dyncyph_detection() {
        let assembly = CilObject::from_path_with_validation(
            "tests/samples/packers/confuserex/mkaring_constants_dyncyph.exe",
            ValidationConfig::analysis(),
        )
        .expect("Failed to load mkaring_constants_dyncyph.exe");

        // Should find 5 decryptor methods (0x06000004-0x06000008)
        let decryptors = find_decryptor_methods(&assembly);
        assert_eq!(
            decryptors.len(),
            5,
            "mkaring_constants_dyncyph.exe should have 5 decryptor methods"
        );

        // Verify expected tokens
        let expected_tokens: Vec<u32> =
            vec![0x06000004, 0x06000005, 0x06000006, 0x06000007, 0x06000008];
        for expected in &expected_tokens {
            assert!(
                decryptors.iter().any(|t| t.value() == *expected),
                "Expected decryptor 0x{:08X} not found in mkaring_constants_dyncyph.exe",
                expected
            );
        }

        // Verify decryptors have generic parameter (T(int32) signature)
        for token in &decryptors {
            let method_entry = assembly
                .methods()
                .get(token)
                .expect("Decryptor should exist");
            let method = method_entry.value();
            assert_eq!(
                method.signature.params.len(),
                1,
                "Decryptor {:?} should have exactly 1 parameter",
                token
            );
            assert_eq!(
                method.signature.param_count_generic, 1,
                "Decryptor {:?} should be generic (T<> signature)",
                token
            );
        }

        // Dynamic cipher mode does NOT use CFGCtx (unlike cfg=true mode)
        let cfgctx = detect_cfgctx_semantics(&assembly);
        assert!(
            cfgctx.is_none(),
            "mkaring_constants_dyncyph.exe uses Dynamic cipher - should NOT have CFGCtx"
        );
    }

    /// Tests CFG mode detection on `mkaring_constants_cfg.exe`.
    ///
    /// `mkaring_constants_cfg.exe` uses cfg=true (CFGCtx state machine):
    /// - 5 generic decryptor methods with signature T(int32)
    /// - CFGCtx value type with 4 slots (A, B, C, D)
    /// - Call pattern: `ldloca CFGCtx; call Next; xor; call Decryptor`
    /// - Order-dependent state machine decryption
    ///
    /// Config: confuserex_constants_cfg.crproj with cfg="true"
    #[test]
    fn test_mkaring_constants_cfg_detection() {
        let assembly = CilObject::from_path_with_validation(
            "tests/samples/packers/confuserex/mkaring_constants_cfg.exe",
            ValidationConfig::analysis(),
        )
        .expect("Failed to load mkaring_constants_cfg.exe");

        // Should find 5 decryptor methods (generic T(int32) signature)
        let decryptors = find_decryptor_methods(&assembly);
        assert_eq!(
            decryptors.len(),
            5,
            "mkaring_constants_cfg.exe should have 5 decryptor methods"
        );

        // Verify decryptors are generic
        for token in &decryptors {
            let method_entry = assembly
                .methods()
                .get(token)
                .expect("Decryptor should exist");
            let method = method_entry.value();
            assert_eq!(
                method.signature.param_count_generic, 1,
                "Decryptor {:?} should be generic (T<> signature)",
                token
            );
        }

        // CFG mode: CFGCtx MUST be detected
        let semantics = detect_cfgctx_semantics(&assembly)
            .expect("CFGCtx should be detected in mkaring_constants_cfg.exe");

        // Verify type token
        assert_eq!(
            semantics.type_token.map(|t| t.value()),
            Some(0x0200_0011),
            "CFGCtx type should be at token 0x02000011"
        );

        // Verify init method (constructor)
        assert_eq!(
            semantics.init_method.map(|t| t.value()),
            Some(0x0600_004f),
            "CFGCtx constructor should be at token 0x0600004f"
        );

        // Verify update method (Next)
        assert_eq!(
            semantics.update_method.map(|t| t.value()),
            Some(0x0600_0050),
            "CFGCtx.Next method should be at token 0x06000050"
        );

        // Verify multiplier (standard ConfuserEx CFGCtx uses 0x21412321)
        assert_eq!(
            semantics.init_constant,
            Some(0x2141_2321),
            "CFGCtx multiplier should be 0x21412321"
        );

        // Verify slot count
        assert_eq!(semantics.slot_count, 4, "CFGCtx should have 4 slots");

        // Verify slot operations (XOR, ADD, XOR, SUB for slots A, B, C, D)
        assert_eq!(semantics.slot_ops.len(), 4, "Should have 4 slot operations");
        assert_eq!(
            semantics.slot_ops[0].op,
            SsaOpKind::Xor,
            "Slot A should use XOR"
        );
        assert_eq!(
            semantics.slot_ops[1].op,
            SsaOpKind::Add,
            "Slot B should use ADD"
        );
        assert_eq!(
            semantics.slot_ops[2].op,
            SsaOpKind::Xor,
            "Slot C should use XOR"
        );
        assert_eq!(
            semantics.slot_ops[3].op,
            SsaOpKind::Sub,
            "Slot D should use SUB"
        );

        // Verify flag encoding parameters
        assert_eq!(
            semantics.explicit_flag_bit, 7,
            "Explicit flag should be bit 7"
        );
        assert_eq!(
            semantics.update_slot_mask, 0x03,
            "Update slot mask should be 0x03"
        );
        assert_eq!(
            semantics.get_slot_mask, 0x03,
            "Get slot mask should be 0x03"
        );
        assert_eq!(semantics.get_slot_shift, 2, "Get slot shift should be 2");
    }

    /// Tests x86 native code cipher mode detection on `mkaring_constants_x86.exe`.
    ///
    /// `mkaring_constants_x86.exe` uses mode=x86 (native code):
    /// - 5 generic decryptor methods with signature T(int32)
    /// - Uses native x86 machine code for key derivation (Windows-only)
    /// - Decryptor methods have `MethodImplCodeType::NATIVE` flag
    /// - NO CFGCtx state machine (call sites are order-independent)
    ///
    /// Config: confuserex_constants_x86.crproj with mode="x86"
    ///
    /// NOTE: This mode requires NativeMethodConversionPass before emulation.
    #[test]
    #[ignore] // Sample needs to be generated using ConfuserEx on Windows
    fn test_mkaring_constants_x86_detection() {
        let assembly = CilObject::from_path_with_validation(
            "tests/samples/packers/confuserex/mkaring_constants_x86.exe",
            ValidationConfig::analysis(),
        )
        .expect("Failed to load mkaring_constants_x86.exe");

        // Should find 5 decryptor methods (0x06000004-0x06000008)
        let decryptors = find_decryptor_methods(&assembly);
        assert_eq!(
            decryptors.len(),
            5,
            "mkaring_constants_x86.exe should have 5 decryptor methods"
        );

        // Verify decryptors have generic parameter (T(int32) signature)
        for token in &decryptors {
            let method_entry = assembly
                .methods()
                .get(token)
                .expect("Decryptor should exist");
            let method = method_entry.value();
            assert_eq!(
                method.signature.param_count_generic, 1,
                "Decryptor {:?} should be generic (T<> signature)",
                token
            );
        }

        // x86 mode does NOT use CFGCtx (unlike cfg=true mode)
        let cfgctx = detect_cfgctx_semantics(&assembly);
        assert!(
            cfgctx.is_none(),
            "mkaring_constants_x86.exe uses x86 native code - should NOT have CFGCtx"
        );

        // TODO: Add verification of native method detection when implemented
        // Native methods have MethodImplCodeType::NATIVE flag
    }

    /// Helper to count total decryptor calls in an assembly (via IL scanning).
    /// Resolves MethodSpec tokens to their underlying MethodDef for comparison.
    fn count_decryptor_calls(assembly: &CilObject, decryptor_set: &HashSet<Token>) -> usize {
        let mut total = 0;
        for method_entry in assembly.methods().iter() {
            let method = method_entry.value();
            if decryptor_set.contains(&method.token) {
                continue;
            }
            for instr in method.instructions() {
                if instr.flow_type == FlowType::Call {
                    if let Operand::Token(target) = &instr.operand {
                        // Resolve MethodSpec (0x2B) to MethodDef (0x06) if needed
                        let resolved = match target.table() {
                            0x06 => Some(*target),
                            0x2B => assembly
                                .method_specs()
                                .get(target)
                                .and_then(|ms| ms.value().method.token())
                                .filter(|t| t.is_table(TableId::MethodDef)),
                            _ => None,
                        };
                        if let Some(method_def) = resolved {
                            if decryptor_set.contains(&method_def) {
                                total += 1;
                            }
                        }
                    }
                }
            }
        }
        total
    }

    /// Tests call site detection for `mkaring_constants.exe` (Normal mode).
    ///
    /// Normal mode uses simple `ldc.i4 KEY; call Decryptor` pattern.
    /// All call sites should be detectable with direct constant keys.
    #[test]
    fn test_call_sites_mkaring_constants() {
        let assembly = CilObject::from_path_with_validation(
            "tests/samples/packers/confuserex/mkaring_constants.exe",
            ValidationConfig::analysis(),
        )
        .expect("Failed to load mkaring_constants.exe");

        let decryptors = find_decryptor_methods(&assembly);
        assert_eq!(decryptors.len(), 5, "Should find 5 decryptor methods");

        let decryptor_set: HashSet<_> = decryptors.iter().copied().collect();
        let total_calls = count_decryptor_calls(&assembly, &decryptor_set);
        let call_sites = find_call_sites(&assembly, &decryptors);

        // Normal mode: all call sites should be detected with direct constants
        assert!(
            total_calls > 0,
            "mkaring_constants.exe should have decryptor calls"
        );
        assert!(
            !call_sites.is_empty(),
            "Should detect call sites in Normal mode"
        );

        // All Normal mode sites should NOT be state machine (CFG) mode
        for site in &call_sites {
            assert!(
                !site.uses_statemachine,
                "mkaring_constants.exe uses Normal mode - all call sites should not be state machine mode"
            );
        }

        // Verify we detect 100% of call sites
        // mkaring_constants.exe has 37 decryptor calls (verified with monodis)
        assert_eq!(
            total_calls, 37,
            "mkaring_constants.exe should have 37 decryptor calls"
        );
        assert_eq!(
            call_sites.len(),
            total_calls,
            "Should detect all {} call sites in Normal mode (detected {})",
            total_calls,
            call_sites.len()
        );
    }

    /// Tests call site detection for `mkaring_constants_dyncyph.exe` (Dynamic cipher mode).
    ///
    /// Dynamic cipher mode uses the same call pattern as Normal mode,
    /// but with DynCipher for key derivation in Initialize().
    #[test]
    fn test_call_sites_mkaring_constants_dyncyph() {
        let assembly = CilObject::from_path_with_validation(
            "tests/samples/packers/confuserex/mkaring_constants_dyncyph.exe",
            ValidationConfig::analysis(),
        )
        .expect("Failed to load mkaring_constants_dyncyph.exe");

        let decryptors = find_decryptor_methods(&assembly);
        assert_eq!(decryptors.len(), 5, "Should find 5 decryptor methods");

        let decryptor_set: HashSet<_> = decryptors.iter().copied().collect();
        let total_calls = count_decryptor_calls(&assembly, &decryptor_set);
        let call_sites = find_call_sites(&assembly, &decryptors);

        // Verify we detect 100% of call sites
        // mkaring_constants_dyncyph.exe has 37 decryptor calls (verified with monodis)
        assert_eq!(
            total_calls, 37,
            "mkaring_constants_dyncyph.exe should have 37 decryptor calls"
        );
        assert_eq!(
            call_sites.len(),
            total_calls,
            "Should detect all {} call sites in Dynamic cipher mode (detected {})",
            total_calls,
            call_sites.len()
        );

        // Dynamic cipher mode does NOT use CFGCtx state machine
        for site in &call_sites {
            assert!(
                !site.uses_statemachine,
                "mkaring_constants_dyncyph.exe uses Dynamic cipher - all call sites should not be state machine mode"
            );
        }
    }

    /// Tests call site detection for `mkaring_constants_cfg.exe` (CFG mode).
    ///
    /// CFG mode uses `xor; call Decryptor` pattern where the XOR operand
    /// comes from CFGCtx.Next() state machine. Call sites should be detected
    /// as state machine mode (is_statemachine() = true).
    #[test]
    fn test_call_sites_mkaring_constants_cfg() {
        let assembly = CilObject::from_path_with_validation(
            "tests/samples/packers/confuserex/mkaring_constants_cfg.exe",
            ValidationConfig::analysis(),
        )
        .expect("Failed to load mkaring_constants_cfg.exe");

        let decryptors = find_decryptor_methods(&assembly);
        assert_eq!(decryptors.len(), 5, "Should find 5 decryptor methods");

        let decryptor_set: HashSet<_> = decryptors.iter().copied().collect();
        let total_calls = count_decryptor_calls(&assembly, &decryptor_set);
        let call_sites = find_call_sites(&assembly, &decryptors);

        // Verify we detect 100% of call sites
        // mkaring_constants_cfg.exe has 37 decryptor calls (verified with monodis)
        assert_eq!(
            total_calls, 37,
            "mkaring_constants_cfg.exe should have 37 decryptor calls"
        );
        assert_eq!(
            call_sites.len(),
            total_calls,
            "Should detect all {} call sites in CFG mode (detected {})",
            total_calls,
            call_sites.len()
        );

        // CFG mode uses xor before call - all sites should be state machine mode
        let state_machine_sites: Vec<_> =
            call_sites.iter().filter(|s| s.uses_statemachine).collect();
        assert_eq!(
            state_machine_sites.len(),
            call_sites.len(),
            "All call sites in mkaring_constants_cfg.exe should be state machine mode ({} state machine vs {} total)",
            state_machine_sites.len(),
            call_sites.len()
        );
    }

    /// Tests call site detection for `mkaring_constants_x86.exe` (x86 native mode).
    ///
    /// x86 mode uses native code for key derivation but same call pattern as Normal mode.
    #[test]
    #[ignore] // Sample needs to be generated using ConfuserEx on Windows
    fn test_call_sites_mkaring_constants_x86() {
        let assembly = CilObject::from_path_with_validation(
            "tests/samples/packers/confuserex/mkaring_constants_x86.exe",
            ValidationConfig::analysis(),
        )
        .expect("Failed to load mkaring_constants_x86.exe");

        let decryptors = find_decryptor_methods(&assembly);
        assert_eq!(decryptors.len(), 5, "Should find 5 decryptor methods");

        let decryptor_set: HashSet<_> = decryptors.iter().copied().collect();
        let total_calls = count_decryptor_calls(&assembly, &decryptor_set);
        let call_sites = find_call_sites(&assembly, &decryptors);

        // x86 mode: should have decryptor calls
        assert!(
            total_calls > 0,
            "mkaring_constants_x86.exe should have decryptor calls"
        );
        assert!(
            !call_sites.is_empty(),
            "Should detect call sites in x86 mode"
        );

        // x86 mode does NOT use CFGCtx state machine
        for site in &call_sites {
            assert!(
                !site.uses_statemachine,
                "mkaring_constants_x86.exe uses x86 native code - all call sites should not be state machine mode"
            );
        }
    }
}
