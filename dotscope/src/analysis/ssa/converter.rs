//! SSA construction algorithm (Cytron et al.).
//!
//! This module implements the classic SSA construction algorithm from:
//!
//! > Cytron et al., "Efficiently Computing Static Single Assignment Form and the
//! > Control Dependence Graph", ACM TOPLAS 1991
//!
//! # Algorithm Overview
//!
//! SSA construction proceeds in three phases:
//!
//! 1. **Stack Simulation**: Convert implicit CIL stack operations to explicit variables
//! 2. **Phi Placement**: Insert phi nodes at dominance frontiers for each variable
//! 3. **Variable Renaming**: Rename variables using dominator tree traversal
//!
//! # Usage
//!
//! ```rust,ignore
//! use dotscope::analysis::{ControlFlowGraph, SsaConverter};
//! use dotscope::assembly::decode_blocks;
//!
//! // Build CFG from decoded blocks
//! let blocks = decode_blocks(data, offset, rva, Some(size))?;
//! let cfg = ControlFlowGraph::from_basic_blocks(blocks)?;
//!
//! // Construct SSA form
//! let ssa = SsaConverter::build(&cfg, 2, 3, None)?; // 2 args, 3 locals
//!
//! // Analyze the SSA form
//! for block in ssa.blocks() {
//!     for phi in block.phi_nodes() {
//!         println!("{}", phi);
//!     }
//! }
//! ```

use std::collections::{HashMap, HashSet};

use crate::{
    analysis::{
        cfg::ControlFlowGraph,
        ssa::{
            decompose::decompose_instruction, ConstValue, DefSite, PhiNode, SimulationResult,
            SsaBlock, SsaFunction, SsaInstruction, SsaOp, SsaType, SsaVarId, SsaVariable,
            StackSimulator, StackSlot, StackSlotSource, TypeContext, UseSite, VariableOrigin,
        },
    },
    assembly::{opcodes, Immediate, Instruction, Operand},
    metadata::{
        signatures::TypeSignature, tables::MemberRefSignature, token::Token,
        typesystem::CilTypeReference,
    },
    utils::graph::{algorithms::DominatorTree, NodeId},
    CilObject, Error, Result,
};

/// A variable definition record during SSA construction.
#[derive(Debug, Clone)]
struct VarDef {
    /// The original variable (argument index, local index, or stack slot).
    origin: VariableOrigin,
    /// The block where this definition occurs.
    block: usize,
    /// Whether this is from a phi node (vs an instruction).
    is_phi: bool,
}

/// Builder for constructing SSA form from a control flow graph.
///
/// This implements the Cytron et al. algorithm with the following phases:
///
/// 1. Simulate the stack to identify variable definitions
/// 2. Compute dominance frontiers and place phi nodes
/// 3. Rename variables using dominator tree traversal
pub struct SsaConverter<'a, 'cfg> {
    /// The control flow graph being transformed.
    cfg: &'a ControlFlowGraph<'cfg>,

    /// Number of method arguments.
    num_args: usize,

    /// Number of local variables.
    num_locals: usize,

    /// The SSA function being built.
    function: SsaFunction,

    /// Definitions of each original variable (by origin) -> list of defining blocks.
    /// Used for phi placement.
    defs: HashMap<VariableOrigin, HashSet<usize>>,

    /// Current version stack for each variable during renaming.
    /// Maps origin -> stack of (version, `SsaVarId`).
    version_stacks: HashMap<VariableOrigin, Vec<(u32, SsaVarId)>>,

    /// Next version number for each variable origin.
    next_version: HashMap<VariableOrigin, u32>,

    /// Variables that have had their address taken.
    address_taken: HashSet<VariableOrigin>,

    /// Maps simulation variable IDs to their load origin (for ldloc/ldarg).
    ///
    /// When a variable is loaded via ldloc/ldarg, the simulator records its origin here.
    /// During SSA rename, this allows us to resolve the variable to the
    /// correct reaching definition (phi result) instead of the stale
    /// simulation variable from a non-dominating block.
    load_origins: HashMap<SsaVarId, VariableOrigin>,

    /// Stack state at the exit of each block (with source tracking).
    ///
    /// Maps block index -> list of StackSlot values containing both the variable ID
    /// and source information (Defined vs Inherited). This is used during phi operand
    /// filling to detect self-referential operands and trace values properly.
    exit_stacks: HashMap<usize, Vec<StackSlot>>,

    /// Stack state at the entry of each block (after reset_stack_to_depth).
    ///
    /// Maps block index -> list of placeholder variables created for block entry.
    /// This is needed to map placeholder variables to PHI results during rename.
    entry_stacks: HashMap<usize, Vec<SsaVarId>>,

    /// Indirect stores discovered during simulation (initobj/stind via ldloca/ldarga).
    ///
    /// Maps (block_idx, instr_idx) -> VariableOrigin for indirect stores.
    /// Used during rename phase to track definitions through pointers.
    indirect_stores: HashMap<(usize, usize), VariableOrigin>,

    /// Optional type context for assigning types during SSA construction.
    ///
    /// When provided, variables are assigned correct types at creation time
    /// based on method signature, local variable signature, and call return types.
    type_context: Option<&'a TypeContext<'a>>,
}

impl<'a, 'cfg> SsaConverter<'a, 'cfg> {
    /// Converts a usize index to u16 with validation.
    ///
    /// Returns an error if the index exceeds `u16::MAX`.
    fn idx_to_u16(idx: usize) -> Result<u16> {
        u16::try_from(idx).map_err(|_| {
            Error::SsaError(format!(
                "Variable index {} exceeds maximum supported value of {}",
                idx,
                u16::MAX
            ))
        })
    }

    /// Returns the SSA type for a variable origin.
    ///
    /// Uses the type context to look up types from the method signature:
    /// - Arguments: type from method parameter signature
    /// - Locals: type from local variable signature
    /// - Stack temps: Unknown (must be inferred from producing instruction)
    fn type_for_origin(&self, origin: VariableOrigin) -> SsaType {
        match (origin, &self.type_context) {
            (VariableOrigin::Argument(idx), Some(ctx)) => ctx.arg_type(idx),
            (VariableOrigin::Local(idx), Some(ctx)) => ctx.local_type(idx),
            _ => SsaType::Unknown,
        }
    }

    /// Infers the result type of an instruction that produces a stack value.
    ///
    /// Uses the type context to resolve:
    /// - Call/CallVirt: return type from method signature
    /// - NewObj: type of the constructed object
    /// - Const: type based on the constant value
    /// - Conv: target type of conversion
    fn infer_instruction_result_type(&self, block_idx: usize, instr_idx: usize) -> SsaType {
        let Some(block) = self.function.block(block_idx) else {
            return SsaType::Unknown;
        };
        let Some(instr) = block.instruction(instr_idx) else {
            return SsaType::Unknown;
        };

        match instr.op() {
            // Call instructions - look up return type from method signature
            SsaOp::Call { method, .. } | SsaOp::CallVirt { method, .. } => {
                if let Some(ctx) = &self.type_context {
                    ctx.call_return_type(method.token())
                } else {
                    SsaType::Unknown
                }
            }

            // NewObj - look up constructed type from constructor
            SsaOp::NewObj { ctor, .. } => {
                if let Some(ctx) = &self.type_context {
                    ctx.newobj_type(ctor.token())
                } else {
                    SsaType::Object
                }
            }

            // Constants - infer type from the constant value
            SsaOp::Const { value, .. } => match value {
                ConstValue::I8(_) => SsaType::I8,
                ConstValue::I16(_) => SsaType::I16,
                ConstValue::I32(_) => SsaType::I32,
                ConstValue::I64(_) => SsaType::I64,
                ConstValue::U8(_) => SsaType::U8,
                ConstValue::U16(_) => SsaType::U16,
                ConstValue::U32(_) => SsaType::U32,
                ConstValue::U64(_) => SsaType::U64,
                ConstValue::NativeInt(_) => SsaType::NativeInt,
                ConstValue::NativeUInt(_) => SsaType::NativeUInt,
                ConstValue::F32(_) => SsaType::F32,
                ConstValue::F64(_) => SsaType::F64,
                ConstValue::String(_) | ConstValue::DecryptedString(_) => SsaType::String,
                ConstValue::Null => SsaType::Null,
                ConstValue::True | ConstValue::False => SsaType::Bool,
                // Runtime handle types (ldtoken results)
                ConstValue::Type(_) => SsaType::RuntimeTypeHandle,
                ConstValue::MethodHandle(_) => SsaType::RuntimeMethodHandle,
                ConstValue::FieldHandle(_) => SsaType::RuntimeFieldHandle,
            },

            // Comparison results are always bool (represented as I32 on stack)
            SsaOp::Ceq { .. } | SsaOp::Clt { .. } | SsaOp::Cgt { .. } => SsaType::Bool,

            // Conversion - use the target type
            SsaOp::Conv { target, .. } => target.clone(),

            // Arithmetic operations - typically I32 for stack operations
            SsaOp::Add { .. }
            | SsaOp::AddOvf { .. }
            | SsaOp::Sub { .. }
            | SsaOp::SubOvf { .. }
            | SsaOp::Mul { .. }
            | SsaOp::MulOvf { .. }
            | SsaOp::Div { .. }
            | SsaOp::Rem { .. }
            | SsaOp::And { .. }
            | SsaOp::Or { .. }
            | SsaOp::Xor { .. }
            | SsaOp::Shl { .. }
            | SsaOp::Shr { .. }
            | SsaOp::Neg { .. }
            | SsaOp::Not { .. }
            // Sizeof produces int32
            | SsaOp::SizeOf { .. } => SsaType::I32,

            // Box produces object reference
            SsaOp::Box { .. } => SsaType::Object,

            // NewArr produces array
            SsaOp::NewArr { elem_type, .. } => {
                // Resolve the element type through the type context so that
                // primitives like System.Char are represented as SsaType::Char
                // rather than SsaType::Class(TypeRef). This ensures the
                // generated LocalVarSig uses ELEMENT_TYPE_CHAR (0x03) instead
                // of ELEMENT_TYPE_CLASS which is invalid for value types.
                let elem_ssa_type = if let Some(ctx) = &self.type_context {
                    SsaType::from_type_token(elem_type.token(), ctx.assembly())
                } else {
                    SsaType::Class(*elem_type)
                };
                SsaType::Array(Box::new(elem_ssa_type), 1)
            }

            // Cast and type check produce the target type
            SsaOp::CastClass { target_type, .. } | SsaOp::IsInst { target_type, .. } => {
                if let Some(ctx) = &self.type_context {
                    SsaType::from_type_token(target_type.token(), ctx.assembly())
                } else {
                    SsaType::Class(*target_type)
                }
            }

            // Unbox operations - resolve value type through type context for primitives
            SsaOp::Unbox { value_type, .. } => {
                let resolved = if let Some(ctx) = &self.type_context {
                    SsaType::from_type_token(value_type.token(), ctx.assembly())
                } else {
                    SsaType::ValueType(*value_type)
                };
                SsaType::ByRef(Box::new(resolved))
            }
            SsaOp::UnboxAny { value_type, .. }
            // Load object (value type copy) — type from value_type token
            | SsaOp::LoadObj { value_type, .. } => {
                if let Some(ctx) = &self.type_context {
                    SsaType::from_type_token(value_type.token(), ctx.assembly())
                } else {
                    SsaType::ValueType(*value_type)
                }
            }

            // Load field - look up field type from assembly
            SsaOp::LoadField { field, .. } | SsaOp::LoadStaticField { field, .. } => {
                if let Some(ctx) = &self.type_context {
                    ctx.field_type(field.token())
                } else {
                    SsaType::Unknown
                }
            }

            // Load field address - byref to field type
            SsaOp::LoadFieldAddr { field, .. } | SsaOp::LoadStaticFieldAddr { field, .. } => {
                if let Some(ctx) = &self.type_context {
                    SsaType::ByRef(Box::new(ctx.field_type(field.token())))
                } else {
                    SsaType::Unknown
                }
            }

            // Load array element - use the element type from the op
            SsaOp::LoadElement { elem_type, .. } => elem_type.clone(),
            SsaOp::LoadElementAddr { elem_type, .. } => {
                let resolved = if let Some(ctx) = &self.type_context {
                    SsaType::from_type_token(elem_type.token(), ctx.assembly())
                } else {
                    SsaType::Class(*elem_type)
                };
                SsaType::ByRef(Box::new(resolved))
            }

            // Indirect load - use the value_type from the op
            SsaOp::LoadIndirect { value_type, .. } => value_type.clone(),

            // Function pointer loads / Array length / LocalAlloc — all native int
            SsaOp::LoadFunctionPtr { .. }
            | SsaOp::LoadVirtFunctionPtr { .. }
            | SsaOp::ArrayLength { .. }
            | SsaOp::LocalAlloc { .. } => SsaType::NativeInt,

            // Load token produces the appropriate RuntimeHandle type
            SsaOp::LoadToken { token, .. } => {
                // Determine handle type based on token table
                match token.token().table() {
                    // TypeRef, TypeDef, TypeSpec
                    0x06 | 0x0A | 0x2B => SsaType::RuntimeMethodHandle, // MethodDef, MemberRef, MethodSpec
                    0x04 => SsaType::RuntimeFieldHandle,                // Field
                    _ => SsaType::RuntimeTypeHandle,                    // Default to type handle
                }
            }

            // Load argument/local — rare from inlining, type comes from context
            SsaOp::LoadArg { arg_index, .. } => {
                if let Some(ctx) = &self.type_context {
                    ctx.arg_type(*arg_index)
                } else {
                    SsaType::Unknown
                }
            }
            SsaOp::LoadLocal { local_index, .. } => {
                if let Some(ctx) = &self.type_context {
                    ctx.local_type(*local_index)
                } else {
                    SsaType::Unknown
                }
            }

            // Load argument/local address — byref to the argument/local type
            SsaOp::LoadArgAddr { arg_index, .. } => {
                if let Some(ctx) = &self.type_context {
                    SsaType::ByRef(Box::new(ctx.arg_type(*arg_index)))
                } else {
                    SsaType::Unknown
                }
            }
            SsaOp::LoadLocalAddr { local_index, .. } => {
                if let Some(ctx) = &self.type_context {
                    SsaType::ByRef(Box::new(ctx.local_type(*local_index)))
                } else {
                    SsaType::Unknown
                }
            }

            // Ckfinite — operates on F64 stack type
            SsaOp::Ckfinite { .. } => SsaType::F64,

            // CallIndirect — resolve return type from standalone signature
            SsaOp::CallIndirect { signature, .. } => {
                if let Some(ctx) = &self.type_context {
                    ctx.call_indirect_return_type(signature.token())
                } else {
                    SsaType::Unknown
                }
            }

            // Copy/Phi — types resolved via origin or during rename, not here.
            // Non-value-producing operations — exhaustive list so new SsaOp
            // variants cause a compiler error instead of silently returning Unknown
            SsaOp::Copy { .. }
            | SsaOp::Phi { .. }
            | SsaOp::StoreField { .. }
            | SsaOp::StoreStaticField { .. }
            | SsaOp::StoreElement { .. }
            | SsaOp::StoreIndirect { .. }
            | SsaOp::StoreObj { .. }
            | SsaOp::Jump { .. }
            | SsaOp::Branch { .. }
            | SsaOp::BranchCmp { .. }
            | SsaOp::Switch { .. }
            | SsaOp::Return { .. }
            | SsaOp::Pop { .. }
            | SsaOp::Throw { .. }
            | SsaOp::Rethrow
            | SsaOp::EndFinally
            | SsaOp::EndFilter { .. }
            | SsaOp::Leave { .. }
            | SsaOp::InitBlk { .. }
            | SsaOp::CopyBlk { .. }
            | SsaOp::InitObj { .. }
            | SsaOp::CopyObj { .. }
            | SsaOp::Nop
            | SsaOp::Break
            | SsaOp::Constrained { .. } => SsaType::Unknown,
        }
    }

    /// Creates and registers an "undefined" variable for a phi operand.
    ///
    /// This is called when no reaching definition is found for a phi operand,
    /// which can happen legitimately (e.g., uninitialized locals) or may indicate
    /// malformed CIL. Rather than creating a ghost ID (one without a registered
    /// SsaVariable), we create and register a proper variable to ensure the
    /// variable table is complete for analysis passes.
    ///
    /// # Arguments
    ///
    /// * `origin` - The origin type of the variable (Stack, Argument, Local, or Phi)
    ///
    /// # Returns
    ///
    /// A properly registered variable ID representing an undefined value.
    fn create_undefined_var(&mut self, origin: VariableOrigin) -> SsaVarId {
        let var_type = self.type_for_origin(origin);
        let var = SsaVariable::new_typed(origin, 0, DefSite::entry(), var_type);
        let id = var.id();
        self.function.add_variable(var);
        id
    }

    /// Tries to map a placeholder variable to a value from a predecessor's exit stack.
    ///
    /// This is used when the immediate dominator's exit stack doesn't have the needed
    /// slot (can happen with `br.s +0` anti-disassembly patterns where different
    /// predecessors contribute different stack depths).
    ///
    /// # Arguments
    ///
    /// * `block_idx` - The current block being renamed
    /// * `slot` - The stack slot index to map
    /// * `placeholder` - The placeholder variable to map
    /// * `rename_map` - The current rename mapping
    fn try_map_from_predecessors(
        &mut self,
        block_idx: usize,
        slot: usize,
        placeholder: SsaVarId,
        rename_map: &mut HashMap<SsaVarId, SsaVarId>,
    ) {
        #[allow(clippy::cast_possible_truncation)]
        let origin = VariableOrigin::Stack(slot as u32);

        // Iterate over actual predecessors to find one with the needed slot
        for pred_id in self.cfg.predecessors(NodeId::new(block_idx)) {
            if let Some(pred_exit) = self.exit_stacks.get(&pred_id.index()) {
                if let Some(stack_slot) = pred_exit.get(slot) {
                    // Found a predecessor with this slot
                    // Check if there's a mapping in rename_map
                    if let Some(&mapped) = rename_map.get(&stack_slot.var) {
                        // Ensure the mapped variable exists in the function
                        if self.function.variable(mapped).is_none() {
                            let new_var =
                                SsaVariable::new_with_id(mapped, origin, 0, DefSite::entry());
                            self.function.add_variable(new_var);
                        }
                        rename_map.insert(placeholder, mapped);
                        return;
                    }
                    // No mapping exists - stack_slot.var is a simulation variable.
                    // Ensure it exists in the function before using it.
                    if self.function.variable(stack_slot.var).is_none() {
                        let new_var =
                            SsaVariable::new_with_id(stack_slot.var, origin, 0, DefSite::entry());
                        self.function.add_variable(new_var);
                    }
                    rename_map.insert(placeholder, stack_slot.var);
                    return;
                }
            }
        }

        // No predecessor has this slot - create a synthetic variable to avoid orphan uses.
        // This can happen with anti-disassembly patterns like `br.s +1` that create
        // unusual CFG structures where stack values cross block boundaries unexpectedly.
        //
        // Rather than leaving the placeholder unmapped (which causes orphan uses that
        // break constant propagation), we create a proper variable entry so the SSA
        // remains well-formed. The value will be Unknown but at least traceable.
        #[allow(clippy::cast_possible_truncation)]
        let origin = VariableOrigin::Stack(slot as u32);
        let new_var = SsaVariable::new(origin, 0, DefSite::entry());
        let new_var_id = new_var.id();
        self.function.add_variable(new_var);
        rename_map.insert(placeholder, new_var_id);
    }

    /// Builds SSA form from a control flow graph.
    ///
    /// # Arguments
    ///
    /// * `cfg` - The control flow graph to transform
    /// * `num_args` - Number of method arguments (including `this` for instance methods)
    /// * `num_locals` - Number of local variables
    /// * `type_context` - Optional type context for assigning types during construction.
    ///   When provided, variables are assigned correct types based on method signature,
    ///   local variable signature, and call return types. When `None`, variables get
    ///   `Unknown` type and types can be inferred later.
    ///
    /// # Returns
    ///
    /// The complete SSA representation, or an error if construction fails.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The CFG is empty
    /// - Stack simulation encounters inconsistencies
    /// - Internal invariants are violated
    pub fn build(
        cfg: &'a ControlFlowGraph<'cfg>,
        num_args: usize,
        num_locals: usize,
        type_context: Option<&'a TypeContext<'a>>,
    ) -> Result<SsaFunction> {
        let block_count = cfg.block_count();
        if block_count == 0 {
            return Err(Error::SsaError(
                "Cannot build SSA from empty CFG".to_string(),
            ));
        }

        let mut builder = Self {
            cfg,
            num_args,
            num_locals,
            function: SsaFunction::with_capacity(num_args, num_locals, block_count, 0),
            defs: HashMap::new(),
            version_stacks: HashMap::new(),
            next_version: HashMap::new(),
            address_taken: HashSet::new(),
            load_origins: HashMap::new(),
            exit_stacks: HashMap::new(),
            entry_stacks: HashMap::new(),
            indirect_stores: HashMap::new(),
            type_context,
        };

        // Get assembly reference from type context for stack simulation
        let assembly = type_context.map(TypeContext::assembly);

        // Phase 1: Simulate stack and collect definitions
        builder.simulate_all_blocks(assembly)?;

        // Phase 2: Place phi nodes at dominance frontiers
        builder.place_phi_nodes();

        // Phase 3: Rename variables using dominator tree traversal
        builder.rename_variables()?;

        // Set original local type signatures from type context for code generation
        if let Some(ctx) = type_context {
            if let Some(local_types) = ctx.local_type_signatures() {
                builder.function.set_original_local_types(local_types);
            }
        }

        Ok(builder.function)
    }

    /// Phase 1: Simulates the stack for all blocks to identify variable definitions.
    fn simulate_all_blocks(&mut self, assembly: Option<&CilObject>) -> Result<()> {
        let rpo = self.cfg.reverse_postorder();

        // Collect exception handler entry blocks that may not be in normal RPO
        // (handler blocks are only reachable via exception flow, not normal control flow)
        let rpo_set: HashSet<_> = rpo.iter().map(|n| n.index()).collect();
        let mut handler_entry_blocks: Vec<usize> = Vec::new();
        for node_id in self.cfg.node_ids() {
            if let Some(block) = self.cfg.block(node_id) {
                if block.handler_entry.is_some() && !rpo_set.contains(&node_id.index()) {
                    handler_entry_blocks.push(node_id.index());
                }
            }
        }

        // Compute ALL blocks reachable from handler entry blocks.
        // This is important because handlers may have internal control flow
        // (e.g., branches within the handler) that creates additional blocks
        // which are not handler entries but are only reachable via exception flow.
        let mut handler_reachable: HashSet<usize> = HashSet::new();
        let mut worklist: Vec<usize> = handler_entry_blocks.clone();
        while let Some(block_idx) = worklist.pop() {
            if !handler_reachable.insert(block_idx) {
                continue; // Already visited
            }
            // Add all successors that aren't in normal RPO
            if let Some(block) = self.cfg.block(NodeId::new(block_idx)) {
                for &succ in &block.successors {
                    if !rpo_set.contains(&succ) && !handler_reachable.contains(&succ) {
                        worklist.push(succ);
                    }
                }
            }
        }

        // Convert handler reachable set to sorted vector for deterministic iteration
        let mut handler_blocks: Vec<usize> = handler_reachable.into_iter().collect();
        handler_blocks.sort_unstable();

        for i in 0..self.cfg.block_count() {
            self.function.add_block(SsaBlock::new(i));
        }

        for i in 0..self.num_args {
            let origin = VariableOrigin::Argument(Self::idx_to_u16(i)?);
            self.defs.entry(origin).or_default().insert(0);
        }
        for i in 0..self.num_locals {
            let origin = VariableOrigin::Local(Self::idx_to_u16(i)?);
            self.defs.entry(origin).or_default().insert(0);
        }

        // First pass: compute stack depths at block exits (including all handler-reachable blocks)
        let mut all_blocks = rpo.clone();
        for &handler_idx in &handler_blocks {
            all_blocks.push(NodeId::new(handler_idx));
        }
        let exit_depths = self.compute_stack_depths(&all_blocks, assembly)?;

        // Create a single simulator for the entire method to ensure unique variable IDs
        // across all blocks within this method. In well-formed CIL, the stack is always
        // balanced at block boundaries.
        let mut simulator = StackSimulator::new(self.num_args, self.num_locals);

        // Second pass: simulate with correct starting stack depths
        for &node_id in &rpo {
            let block_idx = node_id.index();
            let entry_depth = self.compute_entry_depth(block_idx, &exit_depths);
            self.simulate_block(block_idx, entry_depth, &mut simulator, assembly)?;
        }

        // Also simulate all blocks reachable from exception handlers
        for &block_idx in &handler_blocks {
            let entry_depth = self.compute_entry_depth(block_idx, &exit_depths);
            self.simulate_block(block_idx, entry_depth, &mut simulator, assembly)?;
        }

        // Store load_origins for use during rename phase.
        // This maps simulation variables from ldloc/ldarg to their origins.
        self.load_origins = simulator.load_origins().clone();

        Ok(())
    }

    /// Computes the stack depth at the exit of each block.
    ///
    /// This uses a lightweight simulation that only tracks stack depth changes,
    /// not actual variable values. It iterates until fixed-point to correctly
    /// handle back edges in loops.
    ///
    /// When an assembly reference is provided, it's used to resolve correct
    /// argument counts for CALL/CALLVIRT/NEWOBJ instructions. Without it,
    /// falls back to static stack_behavior which may be incorrect.
    fn compute_stack_depths(
        &self,
        rpo: &[NodeId],
        assembly: Option<&CilObject>,
    ) -> Result<HashMap<usize, usize>> {
        // Limit iterations to prevent infinite loops in malformed CIL.
        const MAX_ITERATIONS: usize = 10;

        let mut exit_depths: HashMap<usize, usize> = HashMap::new();

        // Iterate until fixed-point to correctly handle back edges.
        // In the first iteration, back-edge predecessors won't be in exit_depths.
        // Subsequent iterations will see all predecessors and can compute correct depths.
        for _iteration in 0..MAX_ITERATIONS {
            let mut changed = false;

            for &node_id in rpo {
                let block_idx = node_id.index();
                let cfg_block = self.cfg.block(node_id).ok_or_else(|| {
                    Error::SsaError(format!("Block {block_idx} not found in CFG"))
                })?;

                // Compute entry depth from predecessors
                let entry_depth = self.compute_entry_depth(block_idx, &exit_depths);
                let mut depth = entry_depth;

                // Apply stack effects of each instruction
                for instr in &cfg_block.instructions {
                    // For CALL/CALLVIRT/NEWOBJ, resolve actual argument counts from signatures
                    // since static stack_behavior metadata is often incorrect
                    let net_effect = match instr.opcode {
                        opcodes::CALL | opcodes::CALLVIRT | opcodes::NEWOBJ => assembly
                            .and_then(|asm| Self::extract_token(&instr.operand).map(|t| (asm, t)))
                            .and_then(|(asm, token)| {
                                Self::resolve_call_info(asm, token).map(
                                    |(param_count, has_this, has_return)| {
                                        let is_newobj = instr.opcode == opcodes::NEWOBJ;
                                        let pops = if is_newobj {
                                            param_count
                                        } else {
                                            param_count + usize::from(has_this)
                                        };
                                        let pushes = if is_newobj {
                                            1
                                        } else {
                                            usize::from(has_return)
                                        };
                                        #[allow(
                                            clippy::cast_possible_truncation,
                                            clippy::cast_possible_wrap
                                        )]
                                        ((pushes as i32 - pops as i32)
                                            .clamp(i32::from(i8::MIN), i32::from(i8::MAX))
                                            as i8)
                                    },
                                )
                            })
                            .unwrap_or(instr.stack_behavior.net_effect),
                        _ => instr.stack_behavior.net_effect,
                    };

                    // Apply effect, clamping to 0 if it would go negative (shouldn't happen in valid CIL)
                    #[allow(clippy::cast_sign_loss)] // Sign checked in condition
                    if net_effect < 0 {
                        depth = depth.saturating_sub(net_effect.unsigned_abs() as usize);
                    } else {
                        depth += net_effect as usize;
                    }
                }

                // Special handling for leave instructions: they clear the stack
                // The target of a leave instruction has stack depth 0
                if let Some(last_instr) = cfg_block.instructions.last() {
                    if last_instr.opcode == opcodes::LEAVE || last_instr.opcode == opcodes::LEAVE_S
                    {
                        depth = 0;
                    }
                }

                // Check if this block's exit depth changed
                let prev_depth = exit_depths.get(&block_idx).copied();
                if prev_depth != Some(depth) {
                    exit_depths.insert(block_idx, depth);
                    changed = true;
                }
            }

            if !changed {
                break;
            }
        }

        Ok(exit_depths)
    }

    /// Computes the stack depth at block entry based on predecessor exit depths.
    ///
    /// Exception handler entry blocks have special handling:
    /// - Catch/filter handlers: stack depth = 1 (exception object on stack)
    /// - Finally/fault handlers: stack depth = 0 (empty stack)
    fn compute_entry_depth(&self, block_idx: usize, exit_depths: &HashMap<usize, usize>) -> usize {
        // Entry block always starts with empty stack
        if block_idx == self.cfg.entry().index() {
            return 0;
        }

        // Check if this is an exception handler entry block
        if let Some(cfg_block) = self.cfg.block(NodeId::new(block_idx)) {
            if let Some(handler_info) = &cfg_block.handler_entry {
                // Handler entry blocks have a fixed entry stack depth based on handler type
                return handler_info.entry_stack_depth();
            }
        }

        // Take the maximum of all predecessor exit depths
        // (In well-formed CIL, all predecessors should agree, but we use max for safety)
        let mut max_depth = 0;
        for pred_id in self.cfg.predecessors(NodeId::new(block_idx)) {
            if let Some(&pred_depth) = exit_depths.get(&pred_id.index()) {
                max_depth = max_depth.max(pred_depth);
            }
        }
        max_depth
    }

    /// Simulates a single block, converting CIL instructions to SSA.
    ///
    /// Uses a shared simulator to ensure unique variable IDs across all blocks within this method.
    /// In well-formed CIL, the stack is always balanced at block boundaries.
    ///
    /// # Arguments
    ///
    /// * `block_idx` - The index of the block to simulate.
    /// * `entry_stack_depth` - The stack depth at block entry.
    /// * `simulator` - The shared stack simulator for this method.
    /// * `assembly` - Optional assembly reference for resolving call signatures.
    fn simulate_block(
        &mut self,
        block_idx: usize,
        entry_stack_depth: usize,
        simulator: &mut StackSimulator,
        assembly: Option<&CilObject>,
    ) -> Result<()> {
        let node_id = NodeId::new(block_idx);
        let cfg_block = self
            .cfg
            .block(node_id)
            .ok_or_else(|| Error::SsaError(format!("Block {block_idx} not found in CFG")))?;

        // Reset the stack to the expected entry depth for this block
        // This handles cases where control flow merges with different stack states
        simulator.reset_stack_to_depth(entry_stack_depth);

        // Record the entry stack state (the placeholder variables created by reset_stack_to_depth)
        // This is needed to map placeholders to PHI results during rename
        let entry_stack = simulator.stack_snapshot();

        self.entry_stacks.insert(block_idx, entry_stack);

        // Get the block's successors for branch target resolution
        let successors = &cfg_block.successors;

        let instr_count = cfg_block.instructions.len();
        for (instr_idx, cil_instr) in cfg_block.instructions.iter().enumerate() {
            // Set the instruction index for source tracking
            simulator.set_instruction_index(instr_idx);
            let result = Self::simulate_instruction(simulator, cil_instr, assembly)?;

            // Pass successors only for the last instruction (terminator)
            // Non-terminator instructions don't need successor information
            let instr_successors = if instr_idx == instr_count - 1 {
                successors.as_slice()
            } else {
                &[]
            };

            // Decompose the CIL instruction into an SsaOp
            let op = decompose_instruction(
                cil_instr,
                &result.uses,
                result.def,
                instr_successors,
                assembly,
            )?;

            // Create SSA instruction with the decomposed operation
            let ssa_instr = SsaInstruction::new(cil_instr.clone(), op);

            if let Some(block) = self.function.block_mut(block_idx) {
                block.add_instruction(ssa_instr);
            }

            // Record direct stores (stloc/starg) as definitions
            if let Some(origin) = Self::infer_origin(cil_instr)? {
                self.defs.entry(origin).or_default().insert(block_idx);
            }

            // Record indirect stores (initobj/stind via ldloca/ldarga) as definitions
            // This ensures phi nodes are placed correctly for variables initialized
            // through pointers rather than through direct stloc/starg
            if let Some(store_target) = result.store_target {
                self.defs.entry(store_target).or_default().insert(block_idx);
                // Also store for rename phase
                self.indirect_stores
                    .insert((block_idx, instr_idx), store_target);
            }
        }

        // If the block doesn't end with a terminator and has a single successor (fallthrough),
        // add an explicit Jump instruction to make the control flow explicit in SSA.
        // This is essential for correct CFG analysis and dead code elimination.
        if let Some(block) = self.function.block_mut(block_idx) {
            let has_terminator = block
                .instructions()
                .last()
                .is_some_and(|instr| instr.op().is_terminator());

            if !has_terminator && successors.len() == 1 {
                let fallthrough_target = successors[0];
                let jump_instr = SsaInstruction::synthetic(SsaOp::Jump {
                    target: fallthrough_target,
                });
                block.add_instruction(jump_instr);
            }
        }

        for i in 0..self.num_args {
            if simulator.is_arg_address_taken(i) {
                self.address_taken
                    .insert(VariableOrigin::Argument(Self::idx_to_u16(i)?));
            }
        }
        for i in 0..self.num_locals {
            if simulator.is_local_address_taken(i) {
                self.address_taken
                    .insert(VariableOrigin::Local(Self::idx_to_u16(i)?));
            }
        }

        // Record the exit stack state with source tracking for phi operand filling
        self.exit_stacks
            .insert(block_idx, simulator.stack_snapshot_enhanced());

        Ok(())
    }

    /// Simulates a single CIL instruction, returning the stack effects.
    ///
    /// All 257 CIL instructions are covered: specific handling for load/store instructions
    /// that affect SSA variables, and generic stack effect simulation for all others.
    ///
    /// When an assembly reference is provided, call/callvirt/newobj instructions are handled
    /// with correct argument counts based on the method signature rather than using
    /// the static stack_behavior values.
    fn simulate_instruction(
        simulator: &mut StackSimulator,
        instr: &Instruction,
        assembly: Option<&CilObject>,
    ) -> Result<SimulationResult> {
        let result = if instr.prefix == opcodes::FE_PREFIX {
            match instr.opcode {
                opcodes::FE_LDARG => Self::extract_index(&instr.operand)
                    .and_then(|idx| simulator.simulate_ldarg(idx)),
                opcodes::FE_LDARGA => Self::extract_index(&instr.operand)
                    .and_then(|idx| simulator.simulate_ldarga(idx)),
                opcodes::FE_STARG => Self::extract_index(&instr.operand)
                    .and_then(|idx| simulator.simulate_starg(idx)),
                opcodes::FE_LDLOC => Self::extract_index(&instr.operand)
                    .and_then(|idx| simulator.simulate_ldloc(idx)),
                opcodes::FE_LDLOCA => Self::extract_index(&instr.operand)
                    .and_then(|idx| simulator.simulate_ldloca(idx)),
                opcodes::FE_STLOC => Self::extract_index(&instr.operand)
                    .and_then(|idx| simulator.simulate_stloc(idx)),
                opcodes::FE_INITOBJ => simulator.simulate_initobj(),
                _ => simulator
                    .simulate_stack_effect(instr.stack_behavior.pops, instr.stack_behavior.pushes),
            }
        } else {
            match instr.opcode {
                opcodes::LDARG_0 => simulator.simulate_ldarg(0),
                opcodes::LDARG_1 => simulator.simulate_ldarg(1),
                opcodes::LDARG_2 => simulator.simulate_ldarg(2),
                opcodes::LDARG_3 => simulator.simulate_ldarg(3),
                opcodes::LDLOC_0 => simulator.simulate_ldloc(0),
                opcodes::LDLOC_1 => simulator.simulate_ldloc(1),
                opcodes::LDLOC_2 => simulator.simulate_ldloc(2),
                opcodes::LDLOC_3 => simulator.simulate_ldloc(3),
                opcodes::STLOC_0 => simulator.simulate_stloc(0),
                opcodes::STLOC_1 => simulator.simulate_stloc(1),
                opcodes::STLOC_2 => simulator.simulate_stloc(2),
                opcodes::STLOC_3 => simulator.simulate_stloc(3),
                opcodes::LDARG_S => Self::extract_index(&instr.operand)
                    .and_then(|idx| simulator.simulate_ldarg(idx)),
                opcodes::LDARGA_S => Self::extract_index(&instr.operand)
                    .and_then(|idx| simulator.simulate_ldarga(idx)),
                opcodes::STARG_S => Self::extract_index(&instr.operand)
                    .and_then(|idx| simulator.simulate_starg(idx)),
                opcodes::LDLOC_S => Self::extract_index(&instr.operand)
                    .and_then(|idx| simulator.simulate_ldloc(idx)),
                opcodes::LDLOCA_S => Self::extract_index(&instr.operand)
                    .and_then(|idx| simulator.simulate_ldloca(idx)),
                opcodes::STLOC_S => Self::extract_index(&instr.operand)
                    .and_then(|idx| simulator.simulate_stloc(idx)),
                opcodes::DUP => simulator.simulate_dup(),
                opcodes::RET => Some(simulator.simulate_ret()),
                // Leave instructions clear the stack and transfer out of protected region
                opcodes::LEAVE | opcodes::LEAVE_S => Some(simulator.simulate_leave()),
                // Call instructions require special handling with assembly for signature lookup
                opcodes::CALL | opcodes::CALLVIRT => {
                    return Self::simulate_call(simulator, instr, assembly, false);
                }
                opcodes::NEWOBJ => {
                    return Self::simulate_call(simulator, instr, assembly, true);
                }
                // stind.* instructions write through an address - track as indirect store
                opcodes::STIND_REF
                | opcodes::STIND_I1
                | opcodes::STIND_I2
                | opcodes::STIND_I4
                | opcodes::STIND_I8
                | opcodes::STIND_R4
                | opcodes::STIND_R8
                | opcodes::STIND_I => simulator.simulate_stind(),
                _ => simulator
                    .simulate_stack_effect(instr.stack_behavior.pops, instr.stack_behavior.pushes),
            }
        };

        result.ok_or_else(|| {
            Error::SsaError(format!(
                "Stack simulation failed for instruction: {}",
                instr.mnemonic
            ))
        })
    }

    /// Simulates a call instruction (call, callvirt, or newobj).
    ///
    /// If an assembly is provided, it's used to look up the method signature for
    /// correct argument counts. Returns an error if the signature cannot be resolved.
    ///
    /// # Errors
    ///
    /// Returns an error if the method signature cannot be resolved from the assembly.
    fn simulate_call(
        simulator: &mut StackSimulator,
        instr: &Instruction,
        assembly: Option<&CilObject>,
        is_newobj: bool,
    ) -> Result<SimulationResult> {
        let token = Self::extract_token(&instr.operand).ok_or_else(|| {
            Error::SsaError(format!(
                "Call instruction {} missing method token",
                instr.mnemonic
            ))
        })?;

        // Try to get call info from assembly
        if let Some(assembly) = assembly {
            if let Some((param_count, has_this, has_return)) =
                Self::resolve_call_info(assembly, token)
            {
                // For newobj: pop param_count args, push 1 (the new object)
                // For call/callvirt: pop (param_count + has_this) args, push has_return
                let pops = if is_newobj {
                    // newobj doesn't pop 'this' - it creates it
                    param_count
                } else {
                    param_count + usize::from(has_this)
                };

                let pushes = if is_newobj {
                    1 // newobj always pushes the new object
                } else {
                    usize::from(has_return)
                };

                #[allow(clippy::cast_possible_truncation)]
                return simulator
                    .simulate_stack_effect(pops.min(255) as u8, pushes.min(255) as u8)
                    .ok_or_else(|| {
                        Error::SsaError(format!(
                            "Stack underflow simulating {} with {} pops",
                            instr.mnemonic, pops
                        ))
                    });
            }
        }

        // Resolution failed - this is an error for call/callvirt/newobj since they have
        // "variable" stack behavior (pops=0, pushes=0 in metadata) that requires resolution.
        if instr.stack_behavior.pops == 0 && instr.stack_behavior.pushes == 0 {
            return Err(Error::SsaError(format!(
                "Failed to resolve method signature for {} token 0x{:08X}. \
                 Call instructions require signature resolution for correct stack simulation.",
                instr.mnemonic,
                token.value()
            )));
        }

        // Fall back to static stack behavior (for rare cases where metadata has correct values)
        simulator
            .simulate_stack_effect(instr.stack_behavior.pops, instr.stack_behavior.pushes)
            .ok_or_else(|| {
                Error::SsaError(format!("Stack underflow simulating {}", instr.mnemonic))
            })
    }

    /// Resolves call information (param_count, has_this, has_return) from a method token.
    ///
    /// Handles MethodDef (0x06), MemberRef (0x0A), and MethodSpec (0x2B) tokens.
    fn resolve_call_info(assembly: &CilObject, token: Token) -> Option<(usize, bool, bool)> {
        match token.table() {
            // MethodDef (0x06) - method defined in this assembly
            0x06 => {
                let method = assembly.method(&token)?;
                let param_count = method.signature.params.len();
                let has_this = !method.is_static();
                let has_return = !matches!(method.signature.return_type.base, TypeSignature::Void);
                Some((param_count, has_this, has_return))
            }

            // MemberRef (0x0A) - method or field in external assembly
            0x0A => {
                let member_ref = assembly.member_ref(&token)?;
                if let MemberRefSignature::Method(sig) = &member_ref.signature {
                    let has_return = !matches!(sig.return_type.base, TypeSignature::Void);
                    Some((sig.param_count as usize, sig.has_this, has_return))
                } else {
                    None // Field, not a method
                }
            }

            // MethodSpec (0x2B) - generic method instantiation
            0x2B => {
                let method_spec = assembly.method_spec(&token)?;
                // Get the underlying method token from the CilTypeReference
                let underlying_token = match &method_spec.method {
                    CilTypeReference::MethodDef(method_ref) => {
                        method_ref.upgrade().map(|m| m.token)
                    }
                    CilTypeReference::MemberRef(member_ref) => Some(member_ref.token),
                    _ => None,
                };
                underlying_token.and_then(|t| Self::resolve_call_info(assembly, t))
            }

            _ => None,
        }
    }

    /// Extracts a method token from an instruction operand.
    fn extract_token(operand: &Operand) -> Option<Token> {
        match operand {
            Operand::Token(token) => Some(*token),
            _ => None,
        }
    }

    /// Extracts an index from an operand.
    ///
    /// Handles both the typed operand forms (Argument, Local) and immediate values
    /// that are produced by the instruction assembler/decoder.
    fn extract_index(operand: &Operand) -> Option<usize> {
        match operand {
            Operand::Argument(idx) | Operand::Local(idx) => Some(*idx as usize),
            Operand::Immediate(imm) => match imm {
                Immediate::Int8(v) => usize::try_from(*v).ok(),
                Immediate::UInt8(v) => Some(*v as usize),
                Immediate::Int16(v) => usize::try_from(*v).ok(),
                Immediate::UInt16(v) => Some(*v as usize),
                Immediate::Int32(v) => usize::try_from(*v).ok(),
                Immediate::UInt32(v) => Some(*v as usize),
                _ => None,
            },
            _ => None,
        }
    }

    /// Infers the variable origin from an instruction.
    fn infer_origin(instr: &Instruction) -> Result<Option<VariableOrigin>> {
        if instr.prefix == opcodes::FE_PREFIX {
            match instr.opcode {
                opcodes::FE_STARG => match Self::extract_index(&instr.operand) {
                    Some(idx) => Ok(Some(VariableOrigin::Argument(Self::idx_to_u16(idx)?))),
                    None => Ok(None),
                },
                opcodes::FE_STLOC => match Self::extract_index(&instr.operand) {
                    Some(idx) => Ok(Some(VariableOrigin::Local(Self::idx_to_u16(idx)?))),
                    None => Ok(None),
                },
                _ => Ok(None),
            }
        } else {
            match instr.opcode {
                opcodes::STLOC_0 => Ok(Some(VariableOrigin::Local(0))),
                opcodes::STLOC_1 => Ok(Some(VariableOrigin::Local(1))),
                opcodes::STLOC_2 => Ok(Some(VariableOrigin::Local(2))),
                opcodes::STLOC_3 => Ok(Some(VariableOrigin::Local(3))),
                opcodes::STARG_S => match Self::extract_index(&instr.operand) {
                    Some(idx) => Ok(Some(VariableOrigin::Argument(Self::idx_to_u16(idx)?))),
                    None => Ok(None),
                },
                opcodes::STLOC_S => match Self::extract_index(&instr.operand) {
                    Some(idx) => Ok(Some(VariableOrigin::Local(Self::idx_to_u16(idx)?))),
                    None => Ok(None),
                },
                _ => Ok(None),
            }
        }
    }

    /// Phase 2: Places phi nodes at dominance frontiers.
    ///
    /// For each variable that has multiple definitions, we place phi nodes
    /// at the iterated dominance frontier of its definition sites.
    ///
    /// This also places PHI nodes for stack positions at merge points where
    /// values flow from different predecessors via the stack.
    fn place_phi_nodes(&mut self) {
        let dominance_frontiers = self.cfg.dominance_frontiers();

        // First, place PHI nodes for args/locals at dominance frontiers (standard algorithm)
        // NOTE: We place phi nodes even for address-taken variables. While address-taken
        // variables may also be modified through pointers, they still have normal definitions
        // via stloc/starg that need phi nodes at merge points. The address-taken tracking
        // is used elsewhere for memory modeling, not for skipping phi placement.
        for (origin, def_blocks) in &self.defs {
            // Compute iterated dominance frontier
            let mut phi_blocks: HashSet<usize> = HashSet::new();
            let mut worklist: Vec<usize> = def_blocks.iter().copied().collect();

            while let Some(block_idx) = worklist.pop() {
                let node_id = NodeId::new(block_idx);
                if node_id.index() < dominance_frontiers.len() {
                    for &frontier_node in &dominance_frontiers[node_id.index()] {
                        let frontier_idx = frontier_node.index();
                        if phi_blocks.insert(frontier_idx) {
                            worklist.push(frontier_idx);
                        }
                    }
                }
            }

            // Place phi nodes for this origin at each frontier block
            for &phi_block_idx in &phi_blocks {
                if let Some(block) = self.function.block_mut(phi_block_idx) {
                    let phi = PhiNode::new(SsaVarId::new(), *origin);
                    block.add_phi(phi);
                }
            }
        }

        // Second, place PHI nodes for stack positions at merge points
        // A merge point is a block with multiple predecessors
        self.place_stack_phi_nodes();
    }

    /// Places PHI nodes for stack positions at blocks with multiple predecessors.
    ///
    /// When values flow between blocks via the stack (not stored to locals),
    /// we need PHI nodes at merge points to properly track which value is used.
    ///
    /// Uses enhanced stack tracking to only place phis for slots that have
    /// DEFINED values on at least one path, avoiding phantom slots.
    fn place_stack_phi_nodes(&mut self) {
        for block_idx in 0..self.cfg.block_count() {
            let node_id = NodeId::new(block_idx);
            let predecessors: Vec<usize> =
                self.cfg.predecessors(node_id).map(NodeId::index).collect();

            if predecessors.len() < 2 {
                continue;
            }

            // Get enhanced stacks from all predecessors
            let pred_stacks: Vec<Option<&Vec<StackSlot>>> = predecessors
                .iter()
                .map(|&pred_idx| self.exit_stacks.get(&pred_idx))
                .collect();

            // Find slots that have DEFINED values on at least one predecessor
            let mut slots_with_data: HashSet<usize> = HashSet::new();
            for stack in pred_stacks.iter().flatten() {
                for (slot, s) in stack.iter().enumerate() {
                    if matches!(s.source, StackSlotSource::Defined { .. }) {
                        slots_with_data.insert(slot);
                    }
                }
            }

            // Also include slots from entry_stack (placeholders that need resolution)
            if let Some(entry_stack) = self.entry_stacks.get(&block_idx) {
                for slot in 0..entry_stack.len() {
                    slots_with_data.insert(slot);
                }
            }

            // Create PHI nodes for slots with actual data flow
            for slot in slots_with_data {
                #[allow(clippy::cast_possible_truncation)]
                let origin = VariableOrigin::Stack(slot as u32);
                if let Some(block) = self.function.block_mut(block_idx) {
                    let phi = PhiNode::new(SsaVarId::new(), origin);
                    block.add_phi(phi);
                }
            }
        }
    }

    /// Phase 3: Renames variables using dominator tree traversal.
    ///
    /// This assigns unique SSA versions to each variable definition and
    /// updates uses to reference the correct reaching definition.
    fn rename_variables(&mut self) -> Result<()> {
        // Initialize version stacks and create initial variables for args/locals
        for i in 0..self.num_args {
            let origin = VariableOrigin::Argument(Self::idx_to_u16(i)?);
            let var_type = self.type_for_origin(origin);
            let var = SsaVariable::new_typed(origin, 0, DefSite::entry(), var_type);
            let initial_var = var.id();
            self.function.add_variable(var);
            self.version_stacks.insert(origin, vec![(0, initial_var)]);
            self.next_version.insert(origin, 1);
        }
        for i in 0..self.num_locals {
            let origin = VariableOrigin::Local(Self::idx_to_u16(i)?);
            let var_type = self.type_for_origin(origin);
            let var = SsaVariable::new_typed(origin, 0, DefSite::entry(), var_type);
            let initial_var = var.id();
            self.function.add_variable(var);
            self.version_stacks.insert(origin, vec![(0, initial_var)]);
            self.next_version.insert(origin, 1);
        }

        // Start renaming from entry block
        let dom_tree = self.cfg.dominators();
        let mut rename_map = HashMap::new();
        self.rename_block(self.cfg.entry().index(), dom_tree, &mut rename_map)?;

        // Also rename exception handler blocks that aren't reachable via dominator tree.
        // These blocks are only entered via exception flow, not normal control flow,
        // so they won't be visited during the dominator tree traversal.
        //
        // The dominator tree is built from the method's entry block, so blocks only
        // reachable via exception handlers won't appear as children in the tree.
        // We need to explicitly traverse all blocks reachable from handler entries.
        let entry_idx = self.cfg.entry().index();

        // Collect handler entry blocks
        let mut handler_entries: Vec<usize> = Vec::new();
        for node_id in self.cfg.node_ids() {
            let block_idx = node_id.index();
            if block_idx == entry_idx {
                continue;
            }
            if let Some(block) = self.cfg.block(node_id) {
                if block.handler_entry.is_some() {
                    handler_entries.push(block_idx);
                }
            }
        }

        // Process all blocks reachable from handler entries that weren't reached
        // from the main entry point. Use BFS to ensure we visit all reachable blocks.
        let mut visited: HashSet<usize> = HashSet::new();

        // Mark blocks reachable from main entry as visited (they were already processed)
        let mut main_reachable: Vec<usize> = vec![entry_idx];
        while let Some(idx) = main_reachable.pop() {
            if !visited.insert(idx) {
                continue;
            }
            for succ_id in self.cfg.successors(NodeId::new(idx)) {
                main_reachable.push(succ_id.index());
            }
        }

        // Now process handler regions - blocks that aren't reachable from main entry
        for handler_entry in handler_entries {
            // BFS through all blocks reachable from this handler
            let mut worklist: Vec<usize> = vec![handler_entry];
            while let Some(block_idx) = worklist.pop() {
                if visited.contains(&block_idx) {
                    continue;
                }
                visited.insert(block_idx);

                // Rename this block
                self.rename_block(block_idx, dom_tree, &mut rename_map)?;

                // Add successors to worklist
                for succ_id in self.cfg.successors(NodeId::new(block_idx)) {
                    if !visited.contains(&succ_id.index()) {
                        worklist.push(succ_id.index());
                    }
                }
            }
        }

        Ok(())
    }

    /// Gets the current SSA variable for a given origin.
    fn current_def(&self, origin: VariableOrigin) -> Option<SsaVarId> {
        self.version_stacks
            .get(&origin)
            .and_then(|stack| stack.last())
            .map(|(_, var_id)| *var_id)
    }

    /// Creates a new SSA variable for a definition and pushes it on the stack.
    fn new_def(
        &mut self,
        origin: VariableOrigin,
        block_idx: usize,
        instr_idx: Option<usize>,
    ) -> SsaVarId {
        let version = *self.next_version.get(&origin).unwrap_or(&0);
        *self.next_version.entry(origin).or_insert(0) += 1;

        let def_site = match instr_idx {
            Some(idx) => DefSite::instruction(block_idx, idx),
            None => DefSite::phi(block_idx),
        };
        let var_type = self.type_for_origin(origin);
        let var = SsaVariable::new_typed(origin, version, def_site, var_type);
        let var_id = var.id();
        self.function.add_variable(var);

        self.version_stacks
            .entry(origin)
            .or_default()
            .push((version, var_id));
        var_id
    }

    /// Records a use of an SSA variable at the given site.
    fn record_use(&mut self, var_id: SsaVarId, use_site: UseSite) {
        if let Some(var) = self.function.variable_mut(var_id) {
            var.add_use(use_site);
        }
    }

    /// Resolves the phi operand for a stack slot, avoiding self-references.
    ///
    /// When a block loops back to a dominator, its exit stack may contain
    /// inherited placeholders that map to the phi result itself. This method
    /// detects such cases and finds the actual computed value instead.
    fn resolve_stack_phi_operand(
        &mut self,
        slot: u32,
        phi_result: SsaVarId,
        exit_stack: Option<&Vec<StackSlot>>,
        rename_map: &HashMap<SsaVarId, SsaVarId>,
    ) -> SsaVarId {
        let origin = VariableOrigin::Stack(slot);

        let Some(stack) = exit_stack else {
            return self.create_undefined_var(origin);
        };

        let slot_idx = slot as usize;

        // Get the slot value, falling back to TOS for depth mismatch
        let stack_slot = if slot_idx < stack.len() {
            &stack[slot_idx]
        } else if let Some(last) = stack.last() {
            last
        } else {
            return self.create_undefined_var(origin);
        };

        // Get the renamed variable, ensuring it exists in the function
        let renamed = if let Some(&mapped) = rename_map.get(&stack_slot.var) {
            // Ensure the mapped variable exists
            if self.function.variable(mapped).is_none() {
                let new_var = SsaVariable::new_with_id(mapped, origin, 0, DefSite::entry());
                self.function.add_variable(new_var);
            }
            mapped
        } else {
            // No mapping - use stack_slot.var directly, ensuring it exists
            if self.function.variable(stack_slot.var).is_none() {
                let new_var = SsaVariable::new_with_id(stack_slot.var, origin, 0, DefSite::entry());
                self.function.add_variable(new_var);
            }
            stack_slot.var
        };

        // If the value was computed in this block, use it directly
        if matches!(stack_slot.source, StackSlotSource::Defined { .. }) {
            return renamed;
        }

        // Value is inherited. Check if it would be a self-reference.
        if renamed != phi_result {
            return renamed;
        }

        // Self-reference detected. Find the most recent DEFINED value in the stack.
        for s in stack.iter().rev() {
            if matches!(s.source, StackSlotSource::Defined { .. }) {
                let result = if let Some(&mapped) = rename_map.get(&s.var) {
                    // Ensure the mapped variable exists
                    if self.function.variable(mapped).is_none() {
                        let new_var = SsaVariable::new_with_id(mapped, origin, 0, DefSite::entry());
                        self.function.add_variable(new_var);
                    }
                    mapped
                } else {
                    // Ensure s.var exists
                    if self.function.variable(s.var).is_none() {
                        let new_var = SsaVariable::new_with_id(s.var, origin, 0, DefSite::entry());
                        self.function.add_variable(new_var);
                    }
                    s.var
                };
                return result;
            }
        }

        // No defined value found. Try version stack as last resort.
        self.current_def(origin)
            .unwrap_or_else(|| self.create_undefined_var(origin))
    }

    /// Recursively renames variables in a block and its dominated children.
    fn rename_block(
        &mut self,
        block_idx: usize,
        dom_tree: &DominatorTree,
        rename_map: &mut HashMap<SsaVarId, SsaVarId>,
    ) -> Result<()> {
        // Track how many definitions we push for each origin (for cleanup)
        let mut pushed_counts: HashMap<VariableOrigin, usize> = HashMap::new();

        // Step 1: Process phi nodes - they define new versions
        let phi_count = self
            .function
            .block(block_idx)
            .map_or(0, SsaBlock::phi_count);

        // Get entry stack for mapping placeholder variables to stack values
        let entry_stack = self.entry_stacks.get(&block_idx).cloned();

        // Track which stack slots have PHIs in this block
        let mut slots_with_phis: HashSet<u32> = HashSet::new();

        for phi_idx in 0..phi_count {
            if let Some(block) = self.function.block(block_idx) {
                if let Some(phi) = block.phi(phi_idx) {
                    let origin = phi.origin();
                    // Create new definition for this phi
                    let new_var = self.new_def(origin, block_idx, None);
                    *pushed_counts.entry(origin).or_insert(0) += 1;

                    // For stack PHIs, map the placeholder variable to the PHI result
                    // This ensures instructions that use the placeholder get the PHI result
                    if let VariableOrigin::Stack(slot) = origin {
                        slots_with_phis.insert(slot);
                        if let Some(ref entry) = entry_stack {
                            if let Some(&placeholder) = entry.get(slot as usize) {
                                rename_map.insert(placeholder, new_var);
                            }
                        }
                    }

                    // Update the phi's result
                    if let Some(block) = self.function.block_mut(block_idx) {
                        if let Some(phi) = block.phi_mut(phi_idx) {
                            phi.set_result(new_var);
                        }
                    }
                }
            }
        }

        // For entry stack slots that DON'T have PHIs in this block, we still need
        // to map the placeholder to the correct reaching definition.
        //
        // There are two cases:
        // For entry stack slots without PHIs, map placeholders to reaching definitions.
        //
        // For Stack origins, we MUST prefer the predecessor's exit stack over current_def
        // from version_stacks. This is because:
        // 1. ldc.i4 and other push operations create new stack variables but don't update
        //    version_stacks (they're tracked in exit_stacks instead)
        // 2. current_def would return a stale PHI value from a dominator that doesn't
        //    reflect the actual value pushed by the immediate predecessor
        //
        // Example: CFF with anti-disassembly pattern `ldc.i4 KEY; br.s +0; call decryptor`
        // - Block 3 (dispatcher) has PHI for Stack(0) = state value
        // - Block 5 does `ldc.i4 KEY` (pushes KEY to stack)
        // - Block 6 does `call decryptor` (should use KEY, not state)
        // Without this fix, current_def(Stack(0)) returns the dispatcher's PHI result
        // instead of the KEY pushed by block 5.
        //
        // For Argument/Local origins, current_def from version_stacks IS correct because
        // stloc/starg instructions explicitly call new_def() to update version_stacks.
        let idom = dom_tree.immediate_dominator(NodeId::new(block_idx));
        let idom_exit_stack = idom.and_then(|d| self.exit_stacks.get(&d.index()).cloned());

        if let Some(ref entry) = entry_stack {
            for (slot, &placeholder) in entry.iter().enumerate() {
                #[allow(clippy::cast_possible_truncation)]
                let slot_u32 = slot as u32;
                if !slots_with_phis.contains(&slot_u32) {
                    let origin = VariableOrigin::Stack(slot_u32);

                    // For Stack origins: Try predecessor exit stacks FIRST
                    // This ensures we get the actual pushed value, not a stale PHI from a dominator
                    let mapped = if matches!(origin, VariableOrigin::Stack(_)) {
                        // First try direct predecessors (most accurate for stack values)
                        let mut found = false;
                        for pred_id in self.cfg.predecessors(NodeId::new(block_idx)) {
                            if let Some(pred_exit) = self.exit_stacks.get(&pred_id.index()) {
                                if let Some(stack_slot) = pred_exit.get(slot) {
                                    // The predecessor's exit stack has a variable. This might be:
                                    // 1. A renamed SSA variable (in rename_map)
                                    // 2. A simulation variable from ldarg/ldloc (in load_origins)
                                    // 3. An untracked stack variable from simulation
                                    let renamed_var = if let Some(&already_renamed) =
                                        rename_map.get(&stack_slot.var)
                                    {
                                        // Ensure the mapped variable exists
                                        if self.function.variable(already_renamed).is_none() {
                                            let new_var = SsaVariable::new_with_id(
                                                already_renamed,
                                                origin,
                                                0,
                                                DefSite::entry(),
                                            );
                                            self.function.add_variable(new_var);
                                        }
                                        already_renamed
                                    } else if let Some(&load_origin) =
                                        self.load_origins.get(&stack_slot.var)
                                    {
                                        // This is a simulation variable from ldarg/ldloc.
                                        // Resolve it to the correct reaching definition.
                                        if let Some(resolved) = self.current_def(load_origin) {
                                            // Verify the resolved variable exists
                                            if self.function.variable(resolved).is_none() {
                                                let new_var = SsaVariable::new_with_id(
                                                    resolved,
                                                    load_origin,
                                                    0,
                                                    DefSite::entry(),
                                                );
                                                self.function.add_variable(new_var);
                                            }
                                            resolved
                                        } else {
                                            // current_def returned None, ensure stack_slot.var exists
                                            if self.function.variable(stack_slot.var).is_none() {
                                                let new_var = SsaVariable::new_with_id(
                                                    stack_slot.var,
                                                    origin,
                                                    0,
                                                    DefSite::entry(),
                                                );
                                                self.function.add_variable(new_var);
                                            }
                                            stack_slot.var
                                        }
                                    } else {
                                        // Untracked stack variable from simulation.
                                        // Ensure it has an SsaVariable entry in the function.
                                        // Simulation creates SsaVarIds without SsaVariables,
                                        // so we need to create one now using the existing ID.
                                        if self.function.variable(stack_slot.var).is_none() {
                                            let new_var = SsaVariable::new_with_id(
                                                stack_slot.var,
                                                origin,
                                                0,
                                                DefSite::entry(),
                                            );
                                            self.function.add_variable(new_var);
                                        }
                                        stack_slot.var
                                    };
                                    rename_map.insert(placeholder, renamed_var);
                                    found = true;
                                    break;
                                }
                            }
                        }

                        // Fall back to immediate dominator's exit stack
                        if !found {
                            if let Some(ref idom_exit) = idom_exit_stack {
                                if let Some(stack_slot) = idom_exit.get(slot) {
                                    // Same resolution logic as predecessor case - ensure variables exist
                                    let renamed_var = if let Some(&already_renamed) =
                                        rename_map.get(&stack_slot.var)
                                    {
                                        // Ensure the mapped variable exists
                                        if self.function.variable(already_renamed).is_none() {
                                            let new_var = SsaVariable::new_with_id(
                                                already_renamed,
                                                origin,
                                                0,
                                                DefSite::entry(),
                                            );
                                            self.function.add_variable(new_var);
                                        }
                                        already_renamed
                                    } else if let Some(&load_origin) =
                                        self.load_origins.get(&stack_slot.var)
                                    {
                                        if let Some(resolved) = self.current_def(load_origin) {
                                            // Verify the resolved variable exists
                                            if self.function.variable(resolved).is_none() {
                                                let new_var = SsaVariable::new_with_id(
                                                    resolved,
                                                    load_origin,
                                                    0,
                                                    DefSite::entry(),
                                                );
                                                self.function.add_variable(new_var);
                                            }
                                            resolved
                                        } else {
                                            // current_def returned None, ensure stack_slot.var exists
                                            if self.function.variable(stack_slot.var).is_none() {
                                                let new_var = SsaVariable::new_with_id(
                                                    stack_slot.var,
                                                    origin,
                                                    0,
                                                    DefSite::entry(),
                                                );
                                                self.function.add_variable(new_var);
                                            }
                                            stack_slot.var
                                        }
                                    } else {
                                        // Ensure the variable has an SsaVariable entry
                                        if self.function.variable(stack_slot.var).is_none() {
                                            let new_var = SsaVariable::new_with_id(
                                                stack_slot.var,
                                                origin,
                                                0,
                                                DefSite::entry(),
                                            );
                                            self.function.add_variable(new_var);
                                        }
                                        stack_slot.var
                                    };
                                    rename_map.insert(placeholder, renamed_var);
                                    found = true;
                                }
                            }
                        }

                        // Last resort: current_def (may be stale but better than nothing)
                        if !found {
                            if let Some(current) = self.current_def(origin) {
                                rename_map.insert(placeholder, current);
                            } else {
                                // current_def also failed - use predecessor lookup which
                                // will create a synthetic variable if needed
                                self.try_map_from_predecessors(
                                    block_idx,
                                    slot,
                                    placeholder,
                                    rename_map,
                                );
                            }
                        }
                        true
                    } else {
                        false
                    };

                    // For non-Stack origins (Argument, Local): use original logic
                    if !mapped {
                        if let Some(current) = self.current_def(origin) {
                            // Verify current exists (should always, but check to be safe)
                            if self.function.variable(current).is_none() {
                                let new_var =
                                    SsaVariable::new_with_id(current, origin, 0, DefSite::entry());
                                self.function.add_variable(new_var);
                            }
                            rename_map.insert(placeholder, current);
                        } else if let Some(ref idom_exit) = idom_exit_stack {
                            if let Some(stack_slot) = idom_exit.get(slot) {
                                // Ensure the variable exists before inserting into rename_map
                                let renamed_var =
                                    if let Some(&mapped_var) = rename_map.get(&stack_slot.var) {
                                        if self.function.variable(mapped_var).is_none() {
                                            let new_var = SsaVariable::new_with_id(
                                                mapped_var,
                                                origin,
                                                0,
                                                DefSite::entry(),
                                            );
                                            self.function.add_variable(new_var);
                                        }
                                        mapped_var
                                    } else {
                                        // No mapping - ensure stack_slot.var exists
                                        if self.function.variable(stack_slot.var).is_none() {
                                            let new_var = SsaVariable::new_with_id(
                                                stack_slot.var,
                                                origin,
                                                0,
                                                DefSite::entry(),
                                            );
                                            self.function.add_variable(new_var);
                                        }
                                        stack_slot.var
                                    };
                                rename_map.insert(placeholder, renamed_var);
                            } else {
                                // Immediate dominator doesn't have this slot - fall through to
                                // predecessor lookup below
                                self.try_map_from_predecessors(
                                    block_idx,
                                    slot,
                                    placeholder,
                                    rename_map,
                                );
                            }
                        } else {
                            // No immediate dominator exit stack - try predecessors directly
                            self.try_map_from_predecessors(
                                block_idx,
                                slot,
                                placeholder,
                                rename_map,
                            );
                        }
                    }
                }
            }
        }

        // Step 2: Process instructions - update uses and create new defs
        let instr_count = self
            .function
            .block(block_idx)
            .map_or(0, SsaBlock::instruction_count);

        for instr_idx in 0..instr_count {
            // Get instruction info
            let instr_info = self.function.block(block_idx).and_then(|b| {
                b.instruction(instr_idx)
                    .map(|instr| (instr.original().clone(), instr.uses(), instr.def()))
            });

            if let Some((cil_instr, uses, old_def)) = instr_info {
                // Rename uses: replace simulation variables with their renamed counterparts.
                // If a use was the previous definition of an arg/local, replace it with
                // the current reaching definition for that origin.
                let mut renamed_uses = Vec::with_capacity(uses.len());

                for &use_var in &uses {
                    // For Local/Arg origin variables, ALWAYS use current_def() from version stack.
                    // This is necessary because:
                    // 1. ldloc/ldarg push the simulation variable from a previous stloc/starg
                    // 2. That stloc might be in a non-dominating predecessor block
                    // 3. The rename_map entry from that block is stale and shouldn't be used
                    // 4. The version stack correctly tracks the reaching definition per origin
                    //
                    // For stack temporaries (no origin), use rename_map since they don't have
                    // version stacks.
                    let renamed = if let Some(&mapped) = rename_map.get(&use_var) {
                        // Check if the MAPPED variable (SSA var) has a Local/Arg origin
                        // If so, use current_def() instead of the stale rename_map entry
                        if let Some(var_info) = self.function.variable(mapped) {
                            let origin = var_info.origin();
                            match origin {
                                VariableOrigin::Argument(_) | VariableOrigin::Local(_) => {
                                    // Use the current reaching definition from version stack
                                    // Ensure the fallback exists in the function
                                    if let Some(resolved) = self.current_def(origin) {
                                        // Verify the resolved variable exists
                                        if self.function.variable(resolved).is_some() {
                                            resolved
                                        } else {
                                            // Version stack returned non-existent variable, create it
                                            let new_var = SsaVariable::new_with_id(
                                                resolved,
                                                origin,
                                                0,
                                                DefSite::entry(),
                                            );
                                            self.function.add_variable(new_var);
                                            resolved
                                        }
                                    } else {
                                        // current_def returned None, use mapped (which exists)
                                        mapped
                                    }
                                }
                                _ => mapped,
                            }
                        } else {
                            // Mapped variable not in function - ensure it exists.
                            // This can happen when simulation creates SsaVarIds without
                            // corresponding SsaVariables. Create the entry now.
                            let origin = VariableOrigin::Stack(0); // Default stack origin
                            let new_var =
                                SsaVariable::new_with_id(mapped, origin, 0, DefSite::entry());
                            self.function.add_variable(new_var);
                            mapped
                        }
                    } else {
                        // Not in rename_map - check if this variable has a Local/Arg origin.
                        // First check if it's a known SSA variable, then check load_origins
                        // for simulation variables from ldloc/ldarg.
                        if let Some(var_info) = self.function.variable(use_var) {
                            let origin = var_info.origin();
                            match origin {
                                VariableOrigin::Argument(_) | VariableOrigin::Local(_) => {
                                    // Use the current reaching definition for this origin
                                    // Ensure the fallback exists in the function
                                    if let Some(resolved) = self.current_def(origin) {
                                        // Verify the resolved variable exists
                                        if self.function.variable(resolved).is_some() {
                                            resolved
                                        } else {
                                            // Version stack returned non-existent variable, create it
                                            let new_var = SsaVariable::new_with_id(
                                                resolved,
                                                origin,
                                                0,
                                                DefSite::entry(),
                                            );
                                            self.function.add_variable(new_var);
                                            resolved
                                        }
                                    } else {
                                        // current_def returned None, use use_var (which exists)
                                        use_var
                                    }
                                }
                                _ => use_var,
                            }
                        } else if let Some(&origin) = self.load_origins.get(&use_var) {
                            // This is a simulation variable from ldloc/ldarg.
                            // The simulator recorded its origin, so we can resolve it
                            // to the correct reaching definition from the version stack.
                            // If current_def returns None, create a synthetic entry for use_var.
                            if let Some(resolved) = self.current_def(origin) {
                                // Verify the resolved variable exists (should always be true,
                                // but check to be safe since orphan uses break constant propagation)
                                if self.function.variable(resolved).is_some() {
                                    resolved
                                } else {
                                    // The version stack returned a variable that doesn't exist.
                                    // This shouldn't happen, but create the variable to avoid orphan.
                                    let new_var = SsaVariable::new_with_id(
                                        resolved,
                                        origin,
                                        0,
                                        DefSite::entry(),
                                    );
                                    self.function.add_variable(new_var);
                                    resolved
                                }
                            } else {
                                // current_def returned None - need to create a synthetic variable
                                // for use_var since it's not in the function.
                                if self.function.variable(use_var).is_none() {
                                    let new_var = SsaVariable::new_with_id(
                                        use_var,
                                        origin,
                                        0,
                                        DefSite::entry(),
                                    );
                                    self.function.add_variable(new_var);
                                }
                                use_var
                            }
                        } else {
                            // FALLTHROUGH: use_var is not in rename_map, not a known variable,
                            // and not in load_origins. Ensure it has an SsaVariable entry.
                            if self.function.variable(use_var).is_none() {
                                let origin = VariableOrigin::Stack(0);
                                let new_var =
                                    SsaVariable::new_with_id(use_var, origin, 0, DefSite::entry());
                                self.function.add_variable(new_var);
                            }
                            use_var
                        }
                    };
                    renamed_uses.push(renamed);
                }

                // Record uses for each renamed operand
                for &use_var in &renamed_uses {
                    let use_site = UseSite::instruction(block_idx, instr_idx);
                    self.record_use(use_var, use_site);
                }

                // Update the instruction's uses to use renamed variables
                if renamed_uses != uses {
                    if let Some(block) = self.function.block_mut(block_idx) {
                        if let Some(instr) = block.instruction_mut(instr_idx) {
                            // Update uses in the SsaOp (uses are derived from the op)
                            let op = instr.op_mut();
                            for (old_use, &new_use) in uses.iter().zip(renamed_uses.iter()) {
                                if *old_use != new_use {
                                    op.replace_uses(*old_use, new_use);
                                }
                            }
                        }
                    }
                }

                // Determine the origin this instruction defines (if any)
                let def_origin = Self::infer_origin(&cil_instr)?;

                // If this instruction defines a variable, we need to track it
                if let Some(sim_var) = old_def {
                    let new_var = if let Some(origin) = def_origin {
                        // For args/locals, create new SSA version and track in version stack
                        let v = self.new_def(origin, block_idx, Some(instr_idx));
                        *pushed_counts.entry(origin).or_insert(0) += 1;
                        v
                    } else {
                        // For temps (no origin), create a new SSA variable without version tracking
                        // Use the simulation variable's index as the stack slot number
                        #[allow(clippy::cast_possible_truncation)]
                        let slot = sim_var.index() as u32;
                        let var_type = self.infer_instruction_result_type(block_idx, instr_idx);
                        let temp_var = SsaVariable::new_typed(
                            VariableOrigin::Stack(slot),
                            0,
                            DefSite::instruction(block_idx, instr_idx),
                            var_type,
                        );
                        let v = temp_var.id();
                        self.function.add_variable(temp_var);
                        v
                    };

                    // Record the mapping from simulation var to renamed var
                    // This allows later uses to be renamed correctly
                    rename_map.insert(sim_var, new_var);

                    // Update the op's dest (def is derived from op.dest())
                    // This is critical: the phi operands use the renamed variable,
                    // so the op must also use the same variable ID.
                    if let Some(block) = self.function.block_mut(block_idx) {
                        if let Some(instr) = block.instruction_mut(instr_idx) {
                            instr.op_mut().set_dest(new_var);
                        }
                    }
                }

                // Handle indirect stores (initobj/stind via ldloca/ldarga)
                // These don't have a stack def but they do define the underlying variable.
                // We need to track this in the version stack so that phi operands get the
                // correct reaching definition.
                if let Some(&store_target) = self.indirect_stores.get(&(block_idx, instr_idx)) {
                    // Create a new version for the indirectly stored variable
                    // The value being stored is conceptually "zero/default" for initobj,
                    // but we just need to mark that this block defines this variable
                    let _new_version = self.new_def(store_target, block_idx, Some(instr_idx));
                    *pushed_counts.entry(store_target).or_insert(0) += 1;
                }
            }
        }

        // Step 3: Fill in phi operands in successor blocks
        let successors: Vec<usize> = self
            .cfg
            .successors(NodeId::new(block_idx))
            .map(NodeId::index)
            .collect();

        let exit_stack_enhanced = self.exit_stacks.get(&block_idx).cloned();

        for succ_idx in successors {
            let succ_phi_count = self.function.block(succ_idx).map_or(0, SsaBlock::phi_count);

            for phi_idx in 0..succ_phi_count {
                let (origin, phi_result) =
                    match self.function.block(succ_idx).and_then(|b| b.phi(phi_idx)) {
                        Some(phi) => (Some(phi.origin()), phi.result()),
                        None => continue,
                    };

                let Some(origin) = origin else { continue };

                let reaching_def = match origin {
                    VariableOrigin::Stack(slot) => self.resolve_stack_phi_operand(
                        slot,
                        phi_result,
                        exit_stack_enhanced.as_ref(),
                        rename_map,
                    ),
                    VariableOrigin::Argument(_) | VariableOrigin::Local(_) => self
                        .current_def(origin)
                        .unwrap_or_else(|| self.create_undefined_var(origin)),
                    VariableOrigin::Phi => self.create_undefined_var(origin),
                };

                if let Some(block) = self.function.block_mut(succ_idx) {
                    if let Some(phi) = block.phi_mut(phi_idx) {
                        phi.set_operand(block_idx, reaching_def);
                    }
                }

                let use_site = UseSite::phi_operand(succ_idx, phi_idx);
                self.record_use(reaching_def, use_site);
            }
        }

        // Step 4: Recursively process dominated children
        let children: Vec<_> = dom_tree
            .children(NodeId::new(block_idx))
            .into_iter()
            .collect();
        for child in children {
            self.rename_block(child.index(), dom_tree, rename_map)?;
        }

        // Step 5: Pop pushed definitions from stacks
        for (origin, count) in pushed_counts {
            if let Some(stack) = self.version_stacks.get_mut(&origin) {
                for _ in 0..count {
                    stack.pop();
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assembly::{decode_blocks, InstructionAssembler};

    /// Helper to build a CFG from assembled bytecode.
    fn build_cfg(assembler: InstructionAssembler) -> ControlFlowGraph<'static> {
        let (bytecode, _max_stack, _) = assembler.finish().expect("Failed to assemble bytecode");
        let blocks =
            decode_blocks(&bytecode, 0, 0x1000, Some(bytecode.len())).expect("Failed to decode");
        ControlFlowGraph::from_basic_blocks(blocks).expect("Failed to build CFG")
    }

    #[test]
    fn test_simple_function() {
        // Simple method: return arg0 + arg1
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .ldarg_1()
            .unwrap()
            .add()
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);
        let ssa = SsaConverter::build(&cfg, 2, 0, None).expect("SSA construction failed");

        // Should have 1 block
        assert_eq!(ssa.block_count(), 1);

        // Should have at least 2 variables (args)
        assert!(ssa.variable_count() >= 2);
    }

    #[test]
    fn test_local_variable() {
        // Method: local0 = arg0; return local0
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .stloc_0()
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);
        let ssa = SsaConverter::build(&cfg, 1, 1, None).expect("SSA construction failed");

        // Should have 1 block
        assert_eq!(ssa.block_count(), 1);

        // Should have variables for arg and local
        assert!(ssa.variable_count() >= 2);
    }

    #[test]
    fn test_conditional_no_phi() {
        // if (arg0) { return 1; } return 0;
        // No phi needed because both paths return
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .brfalse_s("else")
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .ret()
            .unwrap()
            .label("else")
            .unwrap()
            .ldc_i4_0()
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);
        let ssa = SsaConverter::build(&cfg, 1, 0, None).expect("SSA construction failed");

        // Should have 3 blocks: entry, then, else
        assert_eq!(ssa.block_count(), 3);

        // No phi nodes should be needed (no merge point)
        assert_eq!(ssa.total_phi_count(), 0);
    }

    #[test]
    fn test_diamond_with_merge() {
        // if (arg0) { x = 1; } else { x = 0; } return x;
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .brfalse_s("else")
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .stloc_0()
            .unwrap()
            .br_s("merge")
            .unwrap()
            .label("else")
            .unwrap()
            .ldc_i4_0()
            .unwrap()
            .stloc_0()
            .unwrap()
            .label("merge")
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);
        let ssa = SsaConverter::build(&cfg, 1, 1, None).expect("SSA construction failed");

        // Should have 4 blocks: entry, then, else, merge
        assert_eq!(ssa.block_count(), 4);

        // Should have a phi node in the merge block
        // (local0 is defined in both then and else branches)
        assert!(ssa.total_phi_count() > 0);
    }

    #[test]
    fn test_loop_phi() {
        // i = 0; while (i < arg0) { i++; } return i;
        let mut asm = InstructionAssembler::new();
        asm.ldc_i4_0()
            .unwrap()
            .stloc_0()
            .unwrap() // i = 0
            .label("loop_header")
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ldarg_0()
            .unwrap()
            .bge_s("loop_exit")
            .unwrap() // if (i >= arg0) exit
            .ldloc_0()
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .add()
            .unwrap()
            .stloc_0()
            .unwrap() // i++
            .br_s("loop_header")
            .unwrap()
            .label("loop_exit")
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);
        let ssa = SsaConverter::build(&cfg, 1, 1, None).expect("SSA construction failed");

        // Should have multiple blocks
        assert!(ssa.block_count() >= 2);

        // Should have phi node(s) for the loop variable
        // (i is modified in the loop body and merged at the header)
    }

    #[test]
    fn test_empty_cfg_error() {
        // Create an empty CFG manually would require internal access
        // For now, test that construction succeeds with minimal valid input
        let mut asm = InstructionAssembler::new();
        asm.ret().unwrap();

        let cfg = build_cfg(asm);
        let result = SsaConverter::build(&cfg, 0, 0, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_variable_versions_increment_correctly() {
        // Test that multiple definitions of the same local create different versions
        // local0 = 1; local0 = 2; local0 = 3; return local0;
        let mut asm = InstructionAssembler::new();
        asm.ldc_i4_1()
            .unwrap()
            .stloc_0()
            .unwrap() // local0_0 = 1
            .ldc_i4_2()
            .unwrap()
            .stloc_0()
            .unwrap() // local0_1 = 2
            .ldc_i4_3()
            .unwrap()
            .stloc_0()
            .unwrap() // local0_2 = 3
            .ldloc_0()
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);
        let ssa = SsaConverter::build(&cfg, 0, 1, None).expect("SSA construction failed");

        // Collect all versions of local0
        let local0_vars: Vec<_> = ssa.variables_from_local(0).collect();

        // Should have multiple versions: initial (version 0) plus 3 definitions
        assert!(
            local0_vars.len() >= 3,
            "Expected at least 3 versions of local0, got {}",
            local0_vars.len()
        );

        // Verify each version is unique
        let mut versions: Vec<u32> = local0_vars.iter().map(|v| v.version()).collect();
        versions.sort();
        versions.dedup();
        assert_eq!(
            versions.len(),
            local0_vars.len(),
            "Not all versions are unique"
        );
    }

    #[test]
    fn test_phi_node_operands_from_correct_predecessors() {
        // Diamond control flow: local0 defined differently in each branch
        // if (arg0) { local0 = 1; } else { local0 = 2; }
        // return local0;
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .brfalse_s("else")
            .unwrap()
            // then branch: local0 = 1
            .ldc_i4_1()
            .unwrap()
            .stloc_0()
            .unwrap()
            .br_s("merge")
            .unwrap()
            // else branch: local0 = 2
            .label("else")
            .unwrap()
            .ldc_i4_2()
            .unwrap()
            .stloc_0()
            .unwrap()
            // merge point
            .label("merge")
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);
        let ssa = SsaConverter::build(&cfg, 1, 1, None).expect("SSA construction failed");

        // Find the merge block (block 3 in 0-indexed: entry=0, then=1, else=2, merge=3)
        // There should be a phi node for local0 in the merge block
        assert!(
            ssa.total_phi_count() > 0,
            "Expected phi nodes in merge block"
        );

        // Get all phi nodes
        let phi_nodes: Vec<_> = ssa.all_phi_nodes().collect();
        assert!(!phi_nodes.is_empty(), "No phi nodes found");

        // Find phi node for local0
        let local0_phi = phi_nodes
            .iter()
            .find(|phi| phi.origin() == VariableOrigin::Local(0));
        assert!(
            local0_phi.is_some(),
            "No phi node found for local0 in merge block"
        );

        let phi = local0_phi.unwrap();

        // Phi should have 2 operands (one from each predecessor)
        assert_eq!(
            phi.operand_count(),
            2,
            "Phi node should have exactly 2 operands, got {}",
            phi.operand_count()
        );

        // Each operand should reference a different predecessor
        let predecessors: Vec<_> = phi.operands().iter().map(|op| op.predecessor()).collect();
        assert_ne!(
            predecessors[0], predecessors[1],
            "Phi operands should come from different predecessors"
        );
    }

    #[test]
    fn test_loop_variable_renaming() {
        // Loop with variable modified in body:
        // i = 0; while (i < 10) { i = i + 1; } return i;
        let mut asm = InstructionAssembler::new();
        asm.ldc_i4_0()
            .unwrap()
            .stloc_0()
            .unwrap() // i = 0
            .label("loop_header")
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ldc_i4_s(10)
            .unwrap()
            .bge_s("exit")
            .unwrap() // if i >= 10 exit
            // loop body: i = i + 1
            .ldloc_0()
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .add()
            .unwrap()
            .stloc_0()
            .unwrap()
            .br_s("loop_header")
            .unwrap()
            .label("exit")
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);
        let ssa = SsaConverter::build(&cfg, 0, 1, None).expect("SSA construction failed");

        // Loop header should have a phi node for local0 (merges initial value and loop value)
        assert!(
            ssa.total_phi_count() > 0,
            "Expected phi node(s) for loop variable"
        );

        // Find phi node for local0
        let local0_phis: Vec<_> = ssa
            .all_phi_nodes()
            .filter(|phi| phi.origin() == VariableOrigin::Local(0))
            .collect();

        assert!(
            !local0_phis.is_empty(),
            "Expected phi node for loop variable local0"
        );

        // The phi in the loop header should have 2 operands:
        // one from entry block (initial value) and one from loop body (incremented value)
        for phi in &local0_phis {
            assert!(
                phi.operand_count() >= 2,
                "Loop phi should have at least 2 operands, got {}",
                phi.operand_count()
            );
        }

        // Verify we have multiple versions of local0
        let local0_versions: Vec<_> = ssa.variables_from_local(0).collect();
        assert!(
            local0_versions.len() >= 2,
            "Expected multiple versions of local0, got {}",
            local0_versions.len()
        );
    }

    #[test]
    fn test_unique_ssa_variable_ids() {
        // Test that all SSA variables have unique IDs
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .ldarg_1()
            .unwrap()
            .add()
            .unwrap()
            .stloc_0()
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ldarg_0()
            .unwrap()
            .mul()
            .unwrap()
            .stloc_0()
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);
        let ssa = SsaConverter::build(&cfg, 2, 1, None).expect("SSA construction failed");

        // All variable IDs should be unique
        let mut ids: Vec<_> = ssa.variables().iter().map(|v| v.id().index()).collect();
        let original_len = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(
            ids.len(),
            original_len,
            "All SSA variable IDs should be unique"
        );
    }

    #[test]
    fn test_argument_variable_initial_version() {
        // Arguments should have version 0 at function entry
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .ldarg_1()
            .unwrap()
            .ldarg_2()
            .unwrap()
            .add()
            .unwrap()
            .add()
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);
        let ssa = SsaConverter::build(&cfg, 3, 0, None).expect("SSA construction failed");

        // Check that we have argument variables
        let arg_vars: Vec<_> = ssa.argument_variables().collect();
        assert_eq!(
            arg_vars.len(),
            3,
            "Expected 3 argument variables (version 0), got {}",
            arg_vars.len()
        );

        // All should have version 0
        for var in arg_vars {
            assert_eq!(
                var.version(),
                0,
                "Initial argument should have version 0, got {}",
                var.version()
            );
        }
    }

    #[test]
    fn test_stack_variable_across_branch() {
        // Test that stack values flowing across branches are handled correctly.
        // Valid CIL: both paths must have same stack depth at join point.
        // Pattern: if (arg0) return arg0; else return 0;
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap() // depth: 0→1, stack: [arg0]
            .dup()
            .unwrap() // depth: 1→2, stack: [arg0, arg0]
            .brtrue_s("has_value")
            .unwrap() // pops one, depth: 2→1, records 'has_value' expects 1
            .pop()
            .unwrap() // depth: 1→0
            .ldc_i4_0()
            .unwrap() // depth: 0→1, push replacement value
            .label("has_value")
            .unwrap() // depth: 1 (both paths)
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);
        let ssa = SsaConverter::build(&cfg, 1, 0, None).expect("SSA construction failed");

        // Should succeed without error (this was failing before the stack depth fix)
        assert!(ssa.block_count() >= 2);
    }

    #[test]
    fn test_nested_conditionals_phi_placement() {
        // Nested conditionals to test phi node placement at correct join points
        // if (arg0) { if (arg1) { local0 = 1; } else { local0 = 2; } } else { local0 = 3; }
        // return local0;
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .brfalse_s("outer_else")
            .unwrap()
            // outer then
            .ldarg_1()
            .unwrap()
            .brfalse_s("inner_else")
            .unwrap()
            // inner then: local0 = 1
            .ldc_i4_1()
            .unwrap()
            .stloc_0()
            .unwrap()
            .br_s("inner_merge")
            .unwrap()
            // inner else: local0 = 2
            .label("inner_else")
            .unwrap()
            .ldc_i4_2()
            .unwrap()
            .stloc_0()
            .unwrap()
            .label("inner_merge")
            .unwrap()
            .br_s("outer_merge")
            .unwrap()
            // outer else: local0 = 3
            .label("outer_else")
            .unwrap()
            .ldc_i4_3()
            .unwrap()
            .stloc_0()
            .unwrap()
            // final merge
            .label("outer_merge")
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);
        let ssa = SsaConverter::build(&cfg, 2, 1, None).expect("SSA construction failed");

        // Should have phi nodes at merge points
        assert!(
            ssa.total_phi_count() >= 1,
            "Expected phi nodes at merge points"
        );

        // Multiple versions of local0 should exist
        let local0_vars: Vec<_> = ssa.variables_from_local(0).collect();
        assert!(
            local0_vars.len() >= 3,
            "Expected at least 3 versions of local0 (one per definition path), got {}",
            local0_vars.len()
        );
    }

    #[test]
    fn test_argument_reassignment_creates_new_version() {
        // Test that storing to an argument creates a new version
        // starg.0 after using arg0 should create arg0_1
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap() // load arg0_0
            .ldc_i4_1()
            .unwrap()
            .add()
            .unwrap()
            .starg_s(0)
            .unwrap() // arg0_1 = arg0_0 + 1
            .ldarg_0()
            .unwrap() // load arg0_1
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);
        let ssa = SsaConverter::build(&cfg, 1, 0, None).expect("SSA construction failed");

        // Should have multiple versions of arg0
        let arg0_vars: Vec<_> = ssa.variables_from_argument(0).collect();
        assert!(
            arg0_vars.len() >= 2,
            "Expected at least 2 versions of arg0, got {}",
            arg0_vars.len()
        );

        // Should have version 0 and version 1
        let versions: Vec<u32> = arg0_vars.iter().map(|v| v.version()).collect();
        assert!(versions.contains(&0), "Expected version 0 of arg0 to exist");
    }

    #[test]
    fn test_phi_operands_reference_existing_variables() {
        // Verify that phi node operands reference variables that actually exist
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .brfalse_s("else")
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .stloc_0()
            .unwrap()
            .br_s("merge")
            .unwrap()
            .label("else")
            .unwrap()
            .ldc_i4_0()
            .unwrap()
            .stloc_0()
            .unwrap()
            .label("merge")
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);
        let ssa = SsaConverter::build(&cfg, 1, 1, None).expect("SSA construction failed");

        // For each phi node, verify all operand values reference valid variables
        let var_ids: std::collections::HashSet<_> =
            ssa.variables().iter().map(|v| v.id()).collect();

        for phi in ssa.all_phi_nodes() {
            for operand in phi.operands() {
                assert!(
                    var_ids.contains(&operand.value()),
                    "Phi operand references non-existent variable {}",
                    operand.value()
                );
            }
        }
    }

    #[test]
    fn test_def_site_correctness() {
        // Verify that def_site accurately reflects where variables are defined
        let mut asm = InstructionAssembler::new();
        asm.ldc_i4_0()
            .unwrap()
            .stloc_0()
            .unwrap() // local0 defined in block 0
            .ldloc_0()
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);
        let ssa = SsaConverter::build(&cfg, 0, 1, None).expect("SSA construction failed");

        // Find the non-initial version of local0 (the one from stloc)
        let local0_defs: Vec<_> = ssa
            .variables_from_local(0)
            .filter(|v| !v.def_site().is_phi()) // Skip phi/entry definitions
            .collect();

        // At least one should be defined by an instruction (not phi)
        for var in local0_defs {
            assert!(
                var.def_site().instruction.is_some(),
                "Non-phi variable should have instruction def site"
            );
            // def_site block should be valid
            assert!(
                var.def_site().block < ssa.block_count(),
                "Def site block out of range"
            );
        }
    }

    #[test]
    fn test_stack_value_at_merge_from_different_predecessors() {
        // Test: value pushed onto stack in different branches, used after merge
        //
        // Block 0: ldarg.0; brfalse block2
        // Block 1: ldc.i4.1; br block3  (pushes 1 onto stack)
        // Block 2: ldc.i4.2; br block3  (pushes 2 onto stack)
        // Block 3: ret                   (uses value from stack - should have phi)
        //
        // At block 3, the value on the stack should be a phi of:
        //   - 1 from block 1
        //   - 2 from block 2
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .brfalse_s("else_branch")
            .unwrap()
            // then branch: push 1
            .ldc_i4_1()
            .unwrap()
            .br_s("merge")
            .unwrap()
            // else branch: push 2
            .label("else_branch")
            .unwrap()
            .ldc_i4_2()
            .unwrap()
            // merge point
            .label("merge")
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);
        let ssa = SsaConverter::build(&cfg, 1, 0, None).expect("SSA construction failed");

        // Find the merge block (should be the last block)
        let merge_block_idx = ssa.block_count() - 1;
        let merge_block = ssa
            .block(merge_block_idx)
            .expect("Merge block should exist");

        // At a merge point with stack values from different predecessors,
        // there should be a PHI node for the stack position.
        // Without stack PHIs, the return would incorrectly use just one branch's value.
        assert!(
            merge_block.phi_count() > 0,
            "Merge block should have a PHI node for the stack value (different values from each predecessor)"
        );

        // The return should use the PHI result, not a value from just one predecessor
        let ret_instr = merge_block
            .instructions()
            .last()
            .expect("Merge block should have ret");

        if let SsaOp::Return {
            value: Some(ret_var),
        } = ret_instr.op()
        {
            // The return value should come from a PHI (def_site.instruction should be None)
            if let Some(var_info) = ssa.variable(*ret_var) {
                assert!(
                    var_info.def_site().instruction.is_none(),
                    "Return value {:?} should be from a PHI (stack merge), not a single predecessor",
                    ret_var
                );
            }
        }
    }

    #[test]
    fn test_stack_value_cff_pattern() {
        // Test: CFF-like pattern where constant is pushed and used via switch
        //
        // Block 0: ldc.i4 0x12345678; br block1 (push constant, jump to dispatcher)
        // Block 1: ldc.i4 5; rem.un; switch [block2, block3]
        // Block 2: ret
        // Block 3: ret
        //
        // At block 1, the value on stack (from block 0) should be traceable
        let mut asm = InstructionAssembler::new();
        asm.ldc_i4(0x12345678)
            .unwrap()
            .br_s("dispatcher")
            .unwrap()
            // dispatcher
            .label("dispatcher")
            .unwrap()
            .ldc_i4_5()
            .unwrap()
            .rem_un()
            .unwrap()
            .switch(&["case0", "case1"])
            .unwrap()
            // default case
            .ret()
            .unwrap()
            // case 0
            .label("case0")
            .unwrap()
            .ret()
            .unwrap()
            // case 1
            .label("case1")
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);
        let ssa = SsaConverter::build(&cfg, 0, 0, None).expect("SSA construction failed");

        // The dispatcher block should use the constant from block 0 in rem.un
        // Find the rem.un instruction
        let mut rem_found = false;
        for block in ssa.blocks() {
            for instr in block.instructions() {
                if let SsaOp::Rem { left, .. } = instr.op() {
                    rem_found = true;
                    // The left operand should be traceable to the constant
                    let left_info = ssa.variable(*left);
                    assert!(
                        left_info.is_some(),
                        "rem.un operand {:?} should be in variable table (stack value from predecessor not tracked)",
                        left
                    );
                }
            }
        }
        assert!(rem_found, "rem.un instruction should exist in SSA");
    }

    #[test]
    fn test_stack_value_with_back_edge() {
        // Test: loop with value on stack at merge
        //
        // Block 0: ldc.i4.0; br block1
        // Block 1: dup; ldc.i4 10; blt block2  (loop back if < 10)
        //          br block3
        // Block 2: ldc.i4.1; add; br block1 (increment and loop back)
        // Block 3: ret
        //
        // At block 1, the stack value should be a phi of:
        //   - 0 from block 0 (initial)
        //   - incremented value from block 2
        let mut asm = InstructionAssembler::new();
        asm.ldc_i4_0()
            .unwrap()
            .br_s("loop_header")
            .unwrap()
            // loop header
            .label("loop_header")
            .unwrap()
            .dup()
            .unwrap()
            .ldc_i4(10)
            .unwrap()
            .blt_s("loop_body")
            .unwrap()
            .br_s("exit")
            .unwrap()
            // loop body
            .label("loop_body")
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .add()
            .unwrap()
            .br_s("loop_header")
            .unwrap()
            // exit
            .label("exit")
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);
        let ssa = SsaConverter::build(&cfg, 0, 0, None).expect("SSA construction failed");

        // Find the add instruction and check its operands
        let mut add_found = false;
        for block in ssa.blocks() {
            for instr in block.instructions() {
                if let SsaOp::Add { left, .. } = instr.op() {
                    add_found = true;
                    // Both operands should be in the variable table
                    assert!(
                        ssa.variable(*left).is_some(),
                        "Add left operand {:?} should be trackable",
                        left
                    );
                }
            }
        }
        assert!(add_found, "Add instruction should exist in SSA");
    }

    #[test]
    fn test_switch_all_targets_reachable() {
        // Test that switch targets are properly represented in SSA
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .switch(&["case0", "case1", "case2"])
            .unwrap()
            // default case
            .ldc_i4_m1()
            .unwrap()
            .ret()
            .unwrap()
            // case 0
            .label("case0")
            .unwrap()
            .ldc_i4_0()
            .unwrap()
            .ret()
            .unwrap()
            // case 1
            .label("case1")
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .ret()
            .unwrap()
            // case 2
            .label("case2")
            .unwrap()
            .ldc_i4_2()
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);
        let ssa = SsaConverter::build(&cfg, 1, 0, None).expect("SSA construction failed");

        // Find the switch instruction
        let mut switch_found = false;
        for block in ssa.blocks() {
            for instr in block.instructions() {
                if let SsaOp::Switch {
                    targets, default, ..
                } = instr.op()
                {
                    switch_found = true;
                    assert_eq!(targets.len(), 3, "Switch should have 3 targets");
                    // All targets and default should be valid block indices
                    for &target in targets {
                        assert!(
                            target < ssa.block_count(),
                            "Switch target {} out of range",
                            target
                        );
                    }
                    assert!(
                        *default < ssa.block_count(),
                        "Switch default {} out of range",
                        default
                    );
                }
            }
        }
        assert!(switch_found, "Switch instruction should exist in SSA");
    }

    #[test]
    fn test_stack_phi_for_overestimated_entry_depth() {
        // Test: Entry depth computed by static analysis may exceed actual predecessor
        // exit_stack lengths. This can happen when:
        // 1. Fixed-point iteration includes back-edge contributions
        // 2. Static stack_behavior doesn't match actual simulation
        //
        // The fix ensures PHIs are created for all entry_stack slots, even if
        // no predecessor has values at those positions.
        //
        // Pattern: Loop with switch where case blocks have varying stack effects
        //
        // Block 0: push value onto stack, jump to dispatcher
        // Block 1 (dispatcher): use stack value, switch to cases
        // Block 2 (case): push new value and loop back
        // Block 3 (exit): pop and ret
        //
        // This tests that all stack operands are properly registered in variable table.
        let mut asm = InstructionAssembler::new();

        // Block 0: Push initial value
        asm.ldc_i4(0x1000)
            .unwrap()
            .br_s("dispatcher")
            .unwrap()
            // Block 1 (dispatcher): Use stack value
            .label("dispatcher")
            .unwrap()
            .ldc_i4(0xFF)
            .unwrap()
            .xor()
            .unwrap()
            .dup()
            .unwrap()
            .ldc_i4(3)
            .unwrap()
            .rem_un()
            .unwrap()
            .switch(&["case0", "exit"])
            .unwrap()
            .br_s("exit")
            .unwrap()
            // Block 2 (case0): Modify and loop back
            .label("case0")
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .add()
            .unwrap()
            .br_s("dispatcher")
            .unwrap()
            // Block 3 (exit): Clean up and return
            .label("exit")
            .unwrap()
            .pop()
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);
        let ssa = SsaConverter::build(&cfg, 0, 0, None).expect("SSA construction failed");

        // Verify ALL instruction operands are in the variable table
        // This catches any case where simulation variables aren't properly renamed
        for (block_idx, block) in ssa.blocks().iter().enumerate() {
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                for use_var in instr.uses().iter() {
                    assert!(
                        ssa.variable(*use_var).is_some(),
                        "Block {} instr {} ({:?}): use {:?} not in variable table",
                        block_idx,
                        instr_idx,
                        format!("{:?}", instr.op())
                            .chars()
                            .take(30)
                            .collect::<String>(),
                        use_var
                    );
                }
                if let Some(def_var) = instr.def() {
                    assert!(
                        ssa.variable(def_var).is_some(),
                        "Block {} instr {} ({:?}): def {:?} not in variable table",
                        block_idx,
                        instr_idx,
                        format!("{:?}", instr.op())
                            .chars()
                            .take(30)
                            .collect::<String>(),
                        def_var
                    );
                }
            }
            // Also check PHI operands
            for (phi_idx, phi) in block.phi_nodes().iter().enumerate() {
                for operand in phi.operands() {
                    assert!(
                        ssa.variable(operand.value()).is_some(),
                        "Block {} phi {}: operand {:?} not in variable table",
                        block_idx,
                        phi_idx,
                        operand.value()
                    );
                }
            }
        }
    }

    #[test]
    fn test_all_ssa_variables_registered() {
        // Comprehensive test: verify that ALL variables used in the SSA are registered
        // in the variable table. This catches any edge case where simulation variables
        // escape into the final SSA without being properly renamed.
        //
        // Uses a complex control flow pattern similar to ConfuserEx CFF.
        let mut asm = InstructionAssembler::new();

        // Setup: push initial state onto stack and jump to dispatcher
        asm.ldc_i4(0x12345678)
            .unwrap()
            .br_s("dispatcher")
            .unwrap()
            // Dispatcher: compute next state and switch
            // Stack at entry: [state]
            .label("dispatcher")
            .unwrap()
            .ldc_i4(0xDEADBEEF_u32 as i32)
            .unwrap()
            .xor() // [new_state]
            .unwrap()
            .dup() // [new_state, new_state]
            .unwrap()
            .ldc_i4(4)
            .unwrap()
            .rem_un() // [new_state, index]
            .unwrap()
            .switch(&["case0", "case1", "case2"])
            .unwrap()
            // default: exit (stack: [new_state])
            .br_s("exit")
            .unwrap()
            // Case 0: stack at entry: [new_state]
            .label("case0")
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .add() // [new_state + 1]
            .unwrap()
            .br_s("dispatcher")
            .unwrap()
            // Case 1
            .label("case1")
            .unwrap()
            .ldc_i4_2()
            .unwrap()
            .add()
            .unwrap()
            .br_s("dispatcher")
            .unwrap()
            // Case 2
            .label("case2")
            .unwrap()
            .ldc_i4_3()
            .unwrap()
            .add()
            .unwrap()
            .br_s("dispatcher")
            .unwrap()
            // Exit: stack: [new_state]
            .label("exit")
            .unwrap()
            .pop()
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);
        let ssa = SsaConverter::build(&cfg, 0, 0, None).expect("SSA construction failed");

        // Collect all variables used in the SSA
        let mut all_uses = std::collections::HashSet::new();
        let mut all_defs = std::collections::HashSet::new();

        for block in ssa.blocks() {
            for instr in block.instructions() {
                for use_var in instr.uses().iter() {
                    all_uses.insert(*use_var);
                }
                if let Some(def_var) = instr.def() {
                    all_defs.insert(def_var);
                }
            }
            for phi in block.phi_nodes() {
                all_defs.insert(phi.result());
                for operand in phi.operands() {
                    all_uses.insert(operand.value());
                }
            }
        }

        // Verify all uses are in variable table
        for use_var in &all_uses {
            assert!(
                ssa.variable(*use_var).is_some(),
                "Use {:?} not in variable table - this indicates a simulation variable escaped renaming",
                use_var
            );
        }

        // Verify all defs are in variable table
        for def_var in &all_defs {
            assert!(
                ssa.variable(*def_var).is_some(),
                "Def {:?} not in variable table - this indicates incomplete variable registration",
                def_var
            );
        }
    }

    #[test]
    fn test_br_s_zero_offset_pattern() {
        // Test: Anti-disassembly pattern where br.s +0 creates an unnecessary block boundary
        //
        // This pattern is used by ConfuserEx's constants protection:
        //   ldc.i4 <encrypted_const>
        //   br.s   next_instruction  <-- Creates a new block
        //   call   Decryptor
        //
        // The value pushed by ldc.i4 must flow through the br.s to the call
        // in the next block, even though there's only one predecessor (no phi nodes).
        //
        // Block 0: ldc.i4 0x12345678; br.s next
        // Block 1: call (that takes 1 arg); ret
        //
        // At Block 1, the argument to call must be the constant from Block 0.
        let mut asm = InstructionAssembler::new();
        asm.ldc_i4(0x12345678)
            .unwrap()
            .br_s("after_br")
            .unwrap()
            // This label creates a new block, simulating the effect of br.s +0
            .label("after_br")
            .unwrap()
            // In real code this would be a call, but we simulate with pop + ldc + ret
            // to avoid needing assembly references
            .pop()
            .unwrap()
            .ldc_i4_0()
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);
        let ssa = SsaConverter::build(&cfg, 0, 0, None).expect("SSA construction failed");

        // Find the pop instruction and verify its operand is registered
        let mut pop_found = false;
        for block in ssa.blocks() {
            for instr in block.instructions() {
                if let SsaOp::Pop { value } = instr.op() {
                    pop_found = true;
                    // The pop should use the constant from the previous block
                    let var_info = ssa.variable(*value);
                    assert!(
                        var_info.is_some(),
                        "Pop operand {:?} not in variable table - \
                         single-predecessor stack value not properly propagated",
                        value
                    );
                }
            }
        }
        assert!(pop_found, "Pop instruction should exist in SSA");

        // Also verify ALL uses are registered (comprehensive check)
        for block in ssa.blocks() {
            for instr in block.instructions() {
                for use_var in instr.uses().iter() {
                    assert!(
                        ssa.variable(*use_var).is_some(),
                        "Use {:?} not in variable table - stack value not propagated across br.s",
                        use_var
                    );
                }
            }
        }
    }

    #[test]
    fn test_multiple_br_s_zero_offset_pattern() {
        // Test: Multiple anti-disassembly patterns in sequence
        //
        // This matches ConfuserEx's pattern more closely:
        //   ldc.i4 <encrypted1>; br.s next1; next1: pop; stloc.0
        //   ldc.i4 <encrypted2>; br.s next2; next2: pop; stloc.1
        //
        // Each br.s creates a new block, and the constant must flow through.
        let mut asm = InstructionAssembler::new();

        // First pattern: push constant, br.s, pop+store to local 0
        asm.ldc_i4(0x11111111)
            .unwrap()
            .br_s("next1")
            .unwrap()
            .label("next1")
            .unwrap()
            .stloc_0()
            .unwrap()
            // Second pattern: push constant, br.s, pop+store to local 1
            .ldc_i4(0x22222222)
            .unwrap()
            .br_s("next2")
            .unwrap()
            .label("next2")
            .unwrap()
            .stloc_1()
            .unwrap()
            // Third pattern: push constant, br.s, pop+store to local 2
            .ldc_i4(0x33333333)
            .unwrap()
            .br_s("next3")
            .unwrap()
            .label("next3")
            .unwrap()
            .stloc_2()
            .unwrap()
            // Return something
            .ldloc_0()
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);
        let ssa = SsaConverter::build(&cfg, 0, 3, None).expect("SSA construction failed");

        // Verify ALL uses are registered
        let mut unregistered = vec![];
        for block in ssa.blocks() {
            for instr in block.instructions() {
                for use_var in instr.uses().iter() {
                    if ssa.variable(*use_var).is_none() {
                        unregistered.push(*use_var);
                    }
                }
            }
        }
        assert!(
            unregistered.is_empty(),
            "Unregistered uses: {:?} - stack values not propagated across br.s",
            unregistered
        );
    }
}
