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
//! let ssa = SsaConverter::build(&cfg, 2, 3, &type_provider)?; // 2 args, 3 locals
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
            decompose::decompose_instruction, liveness, phis::place_pruned_phis, ConstValue,
            DefSite, PhiNode, SimulationResult, SsaBlock, SsaFunction, SsaInstruction, SsaOp,
            SsaType, SsaVarId, StackSimulator, StackSlot, StackSlotSource, TypeProvider, UseSite,
            VariableOrigin,
        },
    },
    assembly::{opcodes, Immediate, Instruction, Operand},
    metadata::{
        signatures::TypeSignature,
        tables::{MemberRefSignature, StandAloneSigRaw, StandAloneSignature},
        token::Token,
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

    /// Definitions of each variable (by group ID) -> list of defining blocks.
    /// Used for phi placement.
    defs: HashMap<u32, HashSet<usize>>,

    /// Uses of each variable (by group ID) -> list of using blocks.
    /// Used for pruned SSA phi placement (liveness filtering).
    uses: HashMap<u32, HashSet<usize>>,

    /// Current version stack for each variable during renaming.
    /// Maps group ID -> stack of (version, `SsaVarId`).
    version_stacks: HashMap<u32, Vec<(u32, SsaVarId)>>,

    /// Next version number for each group ID.
    next_version: HashMap<u32, u32>,

    /// Variables (by group ID) that have had their address taken.
    address_taken: HashSet<u32>,

    /// Maps group ID -> VariableOrigin for the group.
    /// Used to look up the origin when creating variables from a group.
    group_origins: HashMap<u32, VariableOrigin>,

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

    /// Maps simulation variable IDs to their stack depth positions.
    ///
    /// Used during rename to assign correct stack-derived origins for temporary
    /// variables (those not covered by `infer_origin`, e.g. add, box, call results).
    var_stack_positions: HashMap<SsaVarId, usize>,

    /// Type provider for assigning types during SSA construction.
    ///
    /// Variables are assigned correct types at creation time based on method
    /// signature, local variable signature, and call return types.
    type_provider: &'a dyn TypeProvider,
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

    /// Returns the origin for a stack slot (always `Phi` — stack temps are synthetic).
    fn stack_slot_origin(&self, _slot: usize) -> VariableOrigin {
        VariableOrigin::Phi
    }

    /// Returns the rename group ID for a stack slot at the given depth.
    #[allow(clippy::cast_possible_truncation)]
    fn stack_group(&self, depth: usize) -> u32 {
        self.num_args as u32 + self.num_locals as u32 + depth as u32
    }

    /// Returns the rename group ID for an argument.
    fn arg_group(&self, idx: u16) -> u32 {
        idx as u32
    }

    /// Returns the rename group ID for a local.
    fn local_group(&self, idx: u16) -> u32 {
        self.num_args as u32 + idx as u32
    }

    /// If a group ID corresponds to a stack slot, returns the slot index.
    fn stack_slot_from_group(&self, group: u32) -> Option<usize> {
        let base = self.num_args as u32 + self.num_locals as u32;
        if group >= base {
            Some((group - base) as usize)
        } else {
            None
        }
    }

    /// Returns the origin for a rename group.
    fn origin_for_group(&self, group: u32) -> VariableOrigin {
        if let Some(origin) = self.group_origins.get(&group) {
            *origin
        } else if (group as usize) < self.num_args {
            VariableOrigin::Argument(group as u16)
        } else if (group as usize) < self.num_args + self.num_locals {
            VariableOrigin::Local((group as usize - self.num_args) as u16)
        } else {
            VariableOrigin::Phi
        }
    }

    /// Returns true if a group ID corresponds to a stack slot.
    fn is_stack_group(&self, group: u32) -> bool {
        group >= self.num_args as u32 + self.num_locals as u32
    }

    /// Returns the SSA type for a variable origin.
    ///
    /// Uses the type context to look up types from the method signature:
    /// - Arguments: type from method parameter signature
    /// - Locals: type from local variable signature
    /// - Stack temps: Unknown (must be inferred from producing instruction)
    fn type_for_origin(&self, origin: VariableOrigin) -> SsaType {
        match origin {
            VariableOrigin::Argument(idx) => self.type_provider.arg_type(idx),
            VariableOrigin::Local(idx) => self.type_provider.local_type(idx),
            VariableOrigin::Phi => SsaType::Unknown,
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

        self.infer_op_result_type(instr.op())
    }

    /// Infers the result type of an SSA operation using the TypeContext.
    ///
    /// This is the core type inference routine that resolves types for all ops,
    /// including context-dependent ones (Call, LoadField, LoadArg, etc.) that
    /// require assembly metadata. The result is stored on `SsaInstruction.result_type`
    /// at construction time so it survives through deobfuscation transforms.
    fn infer_op_result_type(&self, op: &SsaOp) -> SsaType {
        match op {
            // Call instructions - look up return type from method signature
            SsaOp::Call { method, .. } | SsaOp::CallVirt { method, .. } => {
                self.type_provider.call_return_type(method.token())
            }

            // NewObj - look up constructed type from constructor
            SsaOp::NewObj { ctor, .. } => self.type_provider.newobj_type(ctor.token()),

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
                // Resolve the element type through the type provider so that
                // primitives like System.Char are represented as SsaType::Char
                // rather than SsaType::Class(TypeRef).
                let elem_ssa_type = if let Some(asm) = self.type_provider.assembly() {
                    SsaType::from_type_token(elem_type.token(), asm)
                } else {
                    SsaType::Class(*elem_type)
                };
                SsaType::Array(Box::new(elem_ssa_type), 1)
            }

            // Cast and type check produce the target type
            SsaOp::CastClass { target_type, .. } | SsaOp::IsInst { target_type, .. } => {
                if let Some(asm) = self.type_provider.assembly() {
                    SsaType::from_type_token(target_type.token(), asm)
                } else {
                    SsaType::Class(*target_type)
                }
            }

            // Unbox operations - resolve value type through type provider for primitives
            SsaOp::Unbox { value_type, .. } => {
                let resolved = if let Some(asm) = self.type_provider.assembly() {
                    SsaType::from_type_token(value_type.token(), asm)
                } else {
                    SsaType::ValueType(*value_type)
                };
                SsaType::ByRef(Box::new(resolved))
            }
            SsaOp::UnboxAny { value_type, .. }
            // Load object (value type copy) — type from value_type token
            | SsaOp::LoadObj { value_type, .. } => {
                if let Some(asm) = self.type_provider.assembly() {
                    SsaType::from_type_token(value_type.token(), asm)
                } else {
                    SsaType::ValueType(*value_type)
                }
            }

            // Load field - look up field type from assembly
            SsaOp::LoadField { field, .. } | SsaOp::LoadStaticField { field, .. } => {
                self.type_provider.field_type(field.token())
            }

            // Load field address - byref to field type
            SsaOp::LoadFieldAddr { field, .. } | SsaOp::LoadStaticFieldAddr { field, .. } => {
                SsaType::ByRef(Box::new(self.type_provider.field_type(field.token())))
            }

            // Load array element - use the element type from the op
            SsaOp::LoadElement { elem_type, .. } => elem_type.clone(),
            SsaOp::LoadElementAddr { elem_type, .. } => {
                let resolved = if let Some(asm) = self.type_provider.assembly() {
                    SsaType::from_type_token(elem_type.token(), asm)
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

            // Load argument/local — type from type provider
            SsaOp::LoadArg { arg_index, .. } => self.type_provider.arg_type(*arg_index),
            SsaOp::LoadLocal { local_index, .. } => self.type_provider.local_type(*local_index),

            // Load argument/local address — byref to the argument/local type
            SsaOp::LoadArgAddr { arg_index, .. } => {
                SsaType::ByRef(Box::new(self.type_provider.arg_type(*arg_index)))
            }
            SsaOp::LoadLocalAddr { local_index, .. } => {
                SsaType::ByRef(Box::new(self.type_provider.local_type(*local_index)))
            }

            // Ckfinite — operates on F64 stack type
            SsaOp::Ckfinite { .. } => SsaType::F64,

            // CallIndirect — resolve return type from standalone signature
            SsaOp::CallIndirect { signature, .. } => {
                self.type_provider.call_indirect_return_type(signature.token())
            }

            // Copy — inherit type from source operand
            SsaOp::Copy { src, .. } => self
                .function
                .variable(*src)
                .map(|v| v.var_type().clone())
                .unwrap_or(SsaType::Unknown),

            // Phi — types resolved during resolve_phi_types() after rename.
            // Non-value-producing operations — exhaustive list so new SsaOp
            // variants cause a compiler error instead of silently returning Unknown
            SsaOp::Phi { .. }
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
            | SsaOp::Constrained { .. }
            | SsaOp::Volatile
            | SsaOp::Unaligned { .. }
            | SsaOp::TailPrefix
            | SsaOp::Readonly => SsaType::Unknown,
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
        self.function
            .create_variable(origin, 0, DefSite::entry(), var_type)
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
        let origin = self.stack_slot_origin(slot);

        // Iterate over actual predecessors to find one with the needed slot
        for pred_id in self.cfg.predecessors(NodeId::new(block_idx)) {
            if let Some(pred_exit) = self.exit_stacks.get(&pred_id.index()) {
                if let Some(stack_slot) = pred_exit.get(slot) {
                    // Found a predecessor with this slot
                    // Check if there's a mapping in rename_map
                    if let Some(&mapped) = rename_map.get(&stack_slot.var) {
                        // Ensure the mapped variable exists in the function
                        if self.function.variable(mapped).is_none() {
                            let new_id = self.function.create_variable_for_origin(
                                origin,
                                0,
                                DefSite::entry(),
                            );
                            rename_map.insert(placeholder, new_id);
                        } else {
                            rename_map.insert(placeholder, mapped);
                        }
                        return;
                    }
                    // No mapping exists - stack_slot.var is a simulation variable.
                    // Create a proper variable and map both the original and placeholder.
                    let new_id =
                        self.function
                            .create_variable_for_origin(origin, 0, DefSite::entry());
                    rename_map.insert(stack_slot.var, new_id);
                    rename_map.insert(placeholder, new_id);
                    return;
                }
            }
        }

        // No predecessor has this slot - create a synthetic variable to avoid orphan uses.
        let new_var_id = self.create_undefined_var(origin);
        rename_map.insert(placeholder, new_var_id);
    }

    /// Builds SSA form from a control flow graph.
    ///
    /// # Arguments
    ///
    /// * `cfg` - The control flow graph to transform
    /// * `num_args` - Number of method arguments (including `this` for instance methods)
    /// * `num_locals` - Number of local variables
    /// * `type_provider` - Type provider for assigning types during construction.
    ///   Variables are assigned correct types based on method signature,
    ///   local variable signature, and call return types.
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
        type_provider: &'a dyn TypeProvider,
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
            uses: HashMap::new(),
            version_stacks: HashMap::new(),
            next_version: HashMap::new(),
            address_taken: HashSet::new(),
            group_origins: HashMap::new(),
            load_origins: HashMap::new(),
            exit_stacks: HashMap::new(),
            entry_stacks: HashMap::new(),
            indirect_stores: HashMap::new(),
            var_stack_positions: HashMap::new(),
            type_provider,
        };

        // Get assembly reference from type provider for stack simulation
        let assembly = type_provider.assembly();

        // Phase 1: Simulate stack and collect definitions
        builder.simulate_all_blocks(assembly)?;

        // Phase 2: Place phi nodes at dominance frontiers
        builder.place_phi_nodes();

        // Phase 3: Rename variables using dominator tree traversal
        builder.rename_variables()?;

        // Phase 3b: Strip Nops left by LoadLocal/LoadArg resolution during rename.
        // Resolved loads are converted to Nop during rename; removing them here
        // keeps the initial SSA clean and avoids stale instruction indices.
        builder.strip_resolved_loads();

        // Set original local type signatures from type provider for code generation
        if let Some(local_types) = type_provider.local_type_signatures() {
            builder.function.set_original_local_types(local_types);
        }

        // Establish dense variable indexing for O(1) lookups in subsequent passes.
        builder.function.reindex_variables();

        // Validate no Unknown types remain on used variables
        builder.function.validate_types().map_err(Error::SsaError)?;

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
            let idx = Self::idx_to_u16(i)?;
            let group = self.arg_group(idx);
            self.group_origins
                .insert(group, VariableOrigin::Argument(idx));
            self.defs.entry(group).or_default().insert(0);
        }
        for i in 0..self.num_locals {
            let idx = Self::idx_to_u16(i)?;
            let group = self.local_group(idx);
            self.group_origins.insert(group, VariableOrigin::Local(idx));
            self.defs.entry(group).or_default().insert(0);
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

        // Store stack positions for use during rename phase.
        // Maps simulation variable IDs to their stack depth at allocation time.
        self.var_stack_positions = simulator.var_stack_positions().clone();

        // num_locals stays at the original declared count — stack temps use
        // Phi origin and are grouped by rename_groups, not by Local index.
        self.function
            .set_num_locals(self.num_locals, self.num_locals);

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
                    // For CALL/CALLVIRT/NEWOBJ/CALLI, resolve actual argument counts from
                    // signatures since static stack_behavior metadata is often incorrect
                    // (CALLI has VarPop/VarPush so net_effect=0 without resolution)
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
                        opcodes::CALLI => assembly
                            .and_then(|asm| Self::extract_token(&instr.operand).map(|t| (asm, t)))
                            .and_then(|(asm, token)| {
                                Self::resolve_calli_info(asm, token).map(
                                    |(param_count, has_this, has_return)| {
                                        // calli pops: param_count + has_this + 1 (function pointer)
                                        let pops = param_count + usize::from(has_this) + 1;
                                        let pushes = usize::from(has_return);
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

            // Create SSA instruction with the decomposed operation and resolved type
            let result_type = self.infer_op_result_type(&op);
            let ssa_instr = if result_type.is_unknown() {
                SsaInstruction::new(cil_instr.clone(), op)
            } else {
                SsaInstruction::new(cil_instr.clone(), op).with_result_type(result_type)
            };

            if let Some(block) = self.function.block_mut(block_idx) {
                block.add_instruction(ssa_instr);
            }

            // Record direct stores (stloc/starg) as definitions
            if let Some(origin) = Self::infer_origin(cil_instr)? {
                let group = match origin {
                    VariableOrigin::Argument(idx) => self.arg_group(idx),
                    VariableOrigin::Local(idx) => self.local_group(idx),
                    VariableOrigin::Phi => continue,
                };
                self.defs.entry(group).or_default().insert(block_idx);
            }

            // Record loads (ldloc/ldarg) as uses for pruned SSA liveness
            if let Some(use_origin) = Self::infer_use_origin(cil_instr)? {
                let use_group = match use_origin {
                    VariableOrigin::Argument(idx) => self.arg_group(idx),
                    VariableOrigin::Local(idx) => self.local_group(idx),
                    VariableOrigin::Phi => continue,
                };
                self.uses.entry(use_group).or_default().insert(block_idx);
            }

            // Record indirect stores (initobj/stind via ldloca/ldarga) as definitions
            // This ensures phi nodes are placed correctly for variables initialized
            // through pointers rather than through direct stloc/starg
            if let Some(store_target) = result.store_target {
                let store_group = match store_target {
                    VariableOrigin::Argument(idx) => self.arg_group(idx),
                    VariableOrigin::Local(idx) => self.local_group(idx),
                    VariableOrigin::Phi => continue,
                };
                self.defs.entry(store_group).or_default().insert(block_idx);
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
                let idx = Self::idx_to_u16(i)?;
                self.address_taken.insert(self.arg_group(idx));
            }
        }
        for i in 0..self.num_locals {
            if simulator.is_local_address_taken(i) {
                let idx = Self::idx_to_u16(i)?;
                self.address_taken.insert(self.local_group(idx));
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
                // calli requires StandAloneSig resolution for correct stack simulation
                opcodes::CALLI => {
                    return Self::simulate_calli(simulator, instr, assembly);
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

    /// Simulates a `calli` instruction by resolving its `StandAloneSig` token.
    ///
    /// The `calli` instruction pops: `arg0, arg1, ..., argN, function_pointer` and
    /// optionally pushes a return value. The number of arguments and return type are
    /// determined by the standalone method signature referenced by the instruction's
    /// operand token (table 0x11).
    fn simulate_calli(
        simulator: &mut StackSimulator,
        instr: &Instruction,
        assembly: Option<&CilObject>,
    ) -> Result<SimulationResult> {
        let token = Self::extract_token(&instr.operand).ok_or_else(|| {
            Error::SsaError(format!(
                "calli instruction missing StandAloneSig token: {}",
                instr.mnemonic
            ))
        })?;

        if let Some(assembly) = assembly {
            if let Some((param_count, has_this, has_return)) =
                Self::resolve_calli_info(assembly, token)
            {
                // calli pops: param_count + has_this args + 1 function pointer
                let pops = param_count + usize::from(has_this) + 1;
                let pushes = usize::from(has_return);

                #[allow(clippy::cast_possible_truncation)]
                return simulator
                    .simulate_stack_effect(pops.min(255) as u8, pushes.min(255) as u8)
                    .ok_or_else(|| {
                        Error::SsaError(format!(
                            "Stack underflow simulating calli with {} pops",
                            pops
                        ))
                    });
            }
        }

        // Resolution failed — calli has VarPop/VarPush so static metadata is useless
        Err(Error::SsaError(format!(
            "Failed to resolve StandAloneSig for calli token 0x{:08X}. \
             calli requires signature resolution for correct stack simulation.",
            token.value()
        )))
    }

    /// Resolves a `StandAloneSig` token to (param_count, has_this, has_return).
    fn resolve_calli_info(assembly: &CilObject, token: Token) -> Option<(usize, bool, bool)> {
        if token.table() != 0x11 {
            return None;
        }
        let tables = assembly.tables()?;
        let table = tables.table::<StandAloneSigRaw>()?;
        let raw = table.get(token.row())?;
        let blob = assembly.blob()?;
        let owned = raw.to_owned(blob).ok()?;
        match &owned.parsed_signature {
            StandAloneSignature::Method(sig) => {
                let has_return = !matches!(sig.return_type.base, TypeSignature::Void);
                Some((sig.param_count as usize, sig.has_this, has_return))
            }
            _ => None,
        }
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

    /// Infers the variable origin for a load (use) instruction (ldarg/ldloc).
    /// Returns `Some(origin)` for load instructions, `None` for others.
    fn infer_use_origin(instr: &Instruction) -> Result<Option<VariableOrigin>> {
        if instr.prefix == opcodes::FE_PREFIX {
            match instr.opcode {
                opcodes::FE_LDARG | opcodes::FE_LDARGA => {
                    match Self::extract_index(&instr.operand) {
                        Some(idx) => Ok(Some(VariableOrigin::Argument(Self::idx_to_u16(idx)?))),
                        None => Ok(None),
                    }
                }
                opcodes::FE_LDLOC | opcodes::FE_LDLOCA => {
                    match Self::extract_index(&instr.operand) {
                        Some(idx) => Ok(Some(VariableOrigin::Local(Self::idx_to_u16(idx)?))),
                        None => Ok(None),
                    }
                }
                _ => Ok(None),
            }
        } else {
            match instr.opcode {
                opcodes::LDARG_0 => Ok(Some(VariableOrigin::Argument(0))),
                opcodes::LDARG_1 => Ok(Some(VariableOrigin::Argument(1))),
                opcodes::LDARG_2 => Ok(Some(VariableOrigin::Argument(2))),
                opcodes::LDARG_3 => Ok(Some(VariableOrigin::Argument(3))),
                opcodes::LDLOC_0 => Ok(Some(VariableOrigin::Local(0))),
                opcodes::LDLOC_1 => Ok(Some(VariableOrigin::Local(1))),
                opcodes::LDLOC_2 => Ok(Some(VariableOrigin::Local(2))),
                opcodes::LDLOC_3 => Ok(Some(VariableOrigin::Local(3))),
                opcodes::LDARG_S | opcodes::LDARGA_S => match Self::extract_index(&instr.operand) {
                    Some(idx) => Ok(Some(VariableOrigin::Argument(Self::idx_to_u16(idx)?))),
                    None => Ok(None),
                },
                opcodes::LDLOC_S | opcodes::LDLOCA_S => match Self::extract_index(&instr.operand) {
                    Some(idx) => Ok(Some(VariableOrigin::Local(Self::idx_to_u16(idx)?))),
                    None => Ok(None),
                },
                _ => Ok(None),
            }
        }
    }

    /// Infers the variable origin from a store (def) instruction (starg/stloc).
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

        // Compute liveness for pruned SSA: only place phis where variable is live.
        // Build CFG successor list for liveness analysis.
        let block_count = self.cfg.block_count();
        let successors_list: Vec<Vec<usize>> = (0..block_count)
            .map(|i| {
                self.cfg
                    .successors(NodeId::new(i))
                    .map(NodeId::index)
                    .collect()
            })
            .collect();

        let live_in =
            liveness::compute_live_in_blocks(&self.defs, &self.uses, &successors_list, block_count);

        // Place PHI nodes for all groups at dominance frontiers (pruned algorithm)
        // NOTE: We place phi nodes even for address-taken variables. While address-taken
        // variables may also be modified through pointers, they still have normal definitions
        // via stloc/starg that need phi nodes at merge points. The address-taken tracking
        // is used elsewhere for memory modeling, not for skipping phi placement.
        let group_origins = self.group_origins.clone();
        let num_args = self.num_args;
        let num_locals = self.num_locals;
        let _ = place_pruned_phis(
            self.function.blocks_mut(),
            &self.defs,
            &live_in,
            dominance_frontiers,
            None,      // All blocks reachable during initial construction
            &|_| true, // Process all groups
            &|group| {
                group_origins.get(&group).copied().unwrap_or_else(|| {
                    if (group as usize) < num_args {
                        VariableOrigin::Argument(group as u16)
                    } else if (group as usize) < num_args + num_locals {
                        VariableOrigin::Local((group as usize - num_args) as u16)
                    } else {
                        VariableOrigin::Phi
                    }
                })
            },
            None, // No Leave target handling during initial construction
        );

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
                // Check if ALL predecessors carry values from the same Local/Arg
                // origin for this slot. If so, the existing Local/Arg PHI handles
                // the merge and a redundant Stack PHI is not needed.
                if self.all_preds_same_local_arg_origin(&predecessors, slot) {
                    continue;
                }

                let origin = self.stack_slot_origin(slot);
                let group = self.stack_group(slot);
                let phi_var_id =
                    self.function
                        .create_variable_for_origin(origin, 0, DefSite::entry());
                self.function.set_rename_group(phi_var_id, group);
                if let Some(block) = self.function.block_mut(block_idx) {
                    let phi = PhiNode::new(phi_var_id, origin);
                    block.add_phi(phi);
                }
            }
        }
    }

    /// Returns true if ALL predecessors have a Defined exit stack value for `slot`
    /// that traces back to the same Local or Argument origin via `load_origins`.
    ///
    /// When this returns true, the value merge at this slot is already handled by
    /// the Local/Arg PHI — creating a Stack PHI would be redundant and creates
    /// dual-origin variables that break `rebuild_ssa()`.
    fn all_preds_same_local_arg_origin(&self, predecessors: &[usize], slot: usize) -> bool {
        let mut common_origin: Option<VariableOrigin> = None;

        for &pred_idx in predecessors {
            let Some(exit_stack) = self.exit_stacks.get(&pred_idx) else {
                return false;
            };
            let Some(stack_slot) = exit_stack.get(slot) else {
                return false;
            };

            // Only handle Defined values — Inherited values would need tracing
            // back through dominator chains which is complex and error-prone
            if !matches!(stack_slot.source, StackSlotSource::Defined { .. }) {
                return false;
            }

            // Check if this variable traces to a Local/Arg via load_origins
            let Some(&origin) = self.load_origins.get(&stack_slot.var) else {
                return false;
            };

            // Verify it's actually a Local or Argument origin
            if !matches!(
                origin,
                VariableOrigin::Argument(_) | VariableOrigin::Local(_)
            ) {
                return false;
            }

            match common_origin {
                None => common_origin = Some(origin),
                Some(existing) if existing == origin => {}
                _ => return false,
            }
        }

        common_origin.is_some()
    }

    /// Phase 3: Renames variables using dominator tree traversal.
    ///
    /// This assigns unique SSA versions to each variable definition and
    /// updates uses to reference the correct reaching definition.
    fn rename_variables(&mut self) -> Result<()> {
        // Initialize version stacks and create initial variables for args/locals
        for i in 0..self.num_args {
            let idx = Self::idx_to_u16(i)?;
            let origin = VariableOrigin::Argument(idx);
            let group = self.arg_group(idx);
            let var_type = self.type_for_origin(origin);
            self.function.register_origin_type(origin, var_type.clone());
            let initial_var = self
                .function
                .create_variable(origin, 0, DefSite::entry(), var_type);
            self.function.set_rename_group(initial_var, group);
            self.version_stacks.insert(group, vec![(0, initial_var)]);
            self.next_version.insert(group, 1);
        }
        for i in 0..self.num_locals {
            let idx = Self::idx_to_u16(i)?;
            let origin = VariableOrigin::Local(idx);
            let group = self.local_group(idx);
            let var_type = self.type_for_origin(origin);
            self.function.register_origin_type(origin, var_type.clone());
            let initial_var = self
                .function
                .create_variable(origin, 0, DefSite::entry(), var_type);
            self.function.set_rename_group(initial_var, group);
            self.version_stacks.insert(group, vec![(0, initial_var)]);
            self.next_version.insert(group, 1);
        }

        // Create v0 entries for stack groups that have phi nodes.
        // In the old code, num_locals was inflated to include stack depths,
        // so the local init loop above covered them. Now that num_locals is
        // no longer inflated, stack groups need explicit v0 entries so that
        // phi operands from predecessors without definitions can resolve.
        // Scan placed phi nodes to find which stack groups exist.
        let mut stack_groups_needing_v0: HashSet<u32> = HashSet::new();
        for block in self.function.blocks() {
            for phi in block.phi_nodes() {
                let group = self.function.rename_group(phi.result());
                if group != u32::MAX
                    && self.is_stack_group(group)
                    && !self.version_stacks.contains_key(&group)
                {
                    stack_groups_needing_v0.insert(group);
                }
            }
        }
        for group in stack_groups_needing_v0 {
            let origin = VariableOrigin::Phi;
            let var_type = SsaType::Unknown;
            let initial_var = self
                .function
                .create_variable(origin, 0, DefSite::entry(), var_type);
            self.function.set_rename_group(initial_var, group);
            self.version_stacks.insert(group, vec![(0, initial_var)]);
            self.next_version.insert(group, 1);
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

        // Resolve phi types from their operands
        self.resolve_phi_types();

        Ok(())
    }

    /// Resolves Unknown-typed phi variables from their operands.
    ///
    /// After rename, phi nodes may have Unknown type because they were created
    /// before their operands were known. This pass iterates until fixpoint,
    /// propagating non-Unknown types bidirectionally:
    /// - Forward: from phi operands to phi results
    /// - Backward: from phi results to Unknown-typed operands
    ///
    /// After fixpoint, resolves any remaining Unknown-typed variables by
    /// examining their defining instruction's result type.
    fn resolve_phi_types(&mut self) {
        // Phase 1: Fixpoint iteration over phi nodes (bidirectional)
        let mut changed = true;
        while changed {
            changed = false;
            for block_idx in 0..self.function.blocks().len() {
                let phi_count = self.function.block(block_idx).map_or(0, |b| b.phi_count());
                for phi_idx in 0..phi_count {
                    let (result, operand_ids) = {
                        let Some(block) = self.function.block(block_idx) else {
                            continue;
                        };
                        let Some(phi) = block.phi(phi_idx) else {
                            continue;
                        };
                        let result = phi.result();
                        let ops: Vec<SsaVarId> = phi.operands().iter().map(|o| o.value()).collect();
                        (result, ops)
                    };

                    // Find first non-Unknown type among result and all operands
                    let known_type = {
                        let result_type = self
                            .function
                            .variable(result)
                            .map(|v| v.var_type().clone())
                            .filter(|t| !t.is_unknown());

                        result_type.or_else(|| {
                            operand_ids.iter().find_map(|&op_id| {
                                self.function
                                    .variable(op_id)
                                    .map(|v| v.var_type().clone())
                                    .filter(|t| !t.is_unknown())
                            })
                        })
                    };

                    let Some(ty) = known_type else {
                        continue;
                    };

                    // Forward: resolve phi result if Unknown
                    if let Some(var) = self.function.variable(result) {
                        if var.var_type().is_unknown() {
                            if let Some(var) = self.function.variable_mut(result) {
                                var.set_type(ty.clone());
                                changed = true;
                            }
                        }
                    }

                    // Backward: resolve Unknown-typed operands from the phi type
                    for &op_id in &operand_ids {
                        if let Some(var) = self.function.variable(op_id) {
                            if var.var_type().is_unknown() {
                                if let Some(var) = self.function.variable_mut(op_id) {
                                    var.set_type(ty.clone());
                                    changed = true;
                                }
                            }
                        }
                    }
                }
            }
        }

        // Phase 2: Resolve remaining Unknown-typed variables from their def instructions
        let var_count = self.function.variables().len();
        for var_idx in 0..var_count {
            let var_id = SsaVarId::from_index(var_idx);
            let (is_unknown, block, instr_idx) = {
                let Some(var) = self.function.variable(var_id) else {
                    continue;
                };
                let ds = var.def_site();
                (var.var_type().is_unknown(), ds.block, ds.instruction)
            };
            if !is_unknown {
                continue;
            }
            if let Some(idx) = instr_idx {
                let resolved = self.infer_instruction_result_type(block, idx);
                if !resolved.is_unknown() {
                    if let Some(var) = self.function.variable_mut(var_id) {
                        var.set_type(resolved);
                    }
                }
            }
        }

        // Phase 3: Propagate types within rename groups.
        // All variables in the same rename group represent the same logical value
        // and should share the same type. Find the known type per group, then apply.
        let var_count = self.function.variables().len();
        let mut group_types: HashMap<u32, SsaType> = HashMap::new();

        // Collect known types per group
        for var_idx in 0..var_count {
            let var_id = SsaVarId::from_index(var_idx);
            let group = self.function.rename_group(var_id);
            if group == u32::MAX {
                continue;
            }
            if let Some(var) = self.function.variable(var_id) {
                if !var.var_type().is_unknown() {
                    group_types
                        .entry(group)
                        .or_insert_with(|| var.var_type().clone());
                }
            }
        }

        // Apply group types to Unknown-typed variables
        for var_idx in 0..var_count {
            let var_id = SsaVarId::from_index(var_idx);
            let group = self.function.rename_group(var_id);
            if group == u32::MAX {
                continue;
            }
            if let Some(var) = self.function.variable(var_id) {
                if var.var_type().is_unknown() {
                    if let Some(ty) = group_types.get(&group) {
                        if let Some(var) = self.function.variable_mut(var_id) {
                            var.set_type(ty.clone());
                        }
                    }
                }
            }
        }
    }

    /// Strips Nop instructions left by LoadLocal/LoadArg resolution.
    ///
    /// During rename, resolved LoadLocal/LoadArg instructions are converted to
    /// Nop. This method removes them and updates variable DefSites to reflect
    /// the new instruction positions.
    fn strip_resolved_loads(&mut self) {
        for block_idx in 0..self.function.blocks().len() {
            let Some(block) = self.function.block_mut(block_idx) else {
                continue;
            };
            let instructions = block.instructions_mut();

            if !instructions.iter().any(|i| matches!(i.op(), SsaOp::Nop)) {
                continue;
            }

            // Build old→new index remapping for non-Nop instructions
            let mut index_remap: HashMap<usize, usize> = HashMap::new();
            let mut new_idx = 0usize;
            for (old_idx, instr) in instructions.iter().enumerate() {
                if !matches!(instr.op(), SsaOp::Nop) {
                    if old_idx != new_idx {
                        index_remap.insert(old_idx, new_idx);
                    }
                    new_idx += 1;
                }
            }

            instructions.retain(|instr| !matches!(instr.op(), SsaOp::Nop));

            // Update variable DefSites that referenced shifted instructions
            if !index_remap.is_empty() {
                for var in self.function.variables_mut() {
                    let site = var.def_site();
                    if site.block == block_idx {
                        if let Some(old_instr) = site.instruction {
                            if let Some(&new_instr) = index_remap.get(&old_instr) {
                                var.set_def_site(DefSite::instruction(block_idx, new_instr));
                            }
                        }
                    }
                }
            }
        }
    }

    /// Gets the current SSA variable for a given group ID.
    fn current_def(&self, group: u32) -> Option<SsaVarId> {
        self.version_stacks
            .get(&group)
            .and_then(|stack| stack.last())
            .map(|(_, var_id)| *var_id)
    }

    /// Gets the current SSA variable for a given origin (convenience wrapper).
    fn current_def_for_origin(&self, origin: VariableOrigin) -> Option<SsaVarId> {
        let group = match origin {
            VariableOrigin::Argument(idx) => self.arg_group(idx),
            VariableOrigin::Local(idx) => self.local_group(idx),
            VariableOrigin::Phi => return None,
        };
        self.current_def(group)
    }

    /// Creates a new SSA variable for a definition and pushes it on the version stack.
    ///
    /// The caller must provide the correct type for the variable and the
    /// rename group. This ensures every variable gets its type from the
    /// caller who has the right context, rather than guessing internally.
    fn new_def(
        &mut self,
        origin: VariableOrigin,
        group: u32,
        block_idx: usize,
        instr_idx: Option<usize>,
        var_type: SsaType,
    ) -> SsaVarId {
        let version = *self.next_version.get(&group).unwrap_or(&0);
        *self.next_version.entry(group).or_insert(0) += 1;

        let def_site = match instr_idx {
            Some(idx) => DefSite::instruction(block_idx, idx),
            None => DefSite::phi(block_idx),
        };

        let var_id = self
            .function
            .create_variable(origin, version, def_site, var_type);
        self.function.set_rename_group(var_id, group);

        self.version_stacks
            .entry(group)
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
        let origin = self.stack_slot_origin(slot as usize);
        let group = self.stack_group(slot as usize);

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
            self.ensure_or_create(mapped, origin)
        } else {
            // No mapping - use stack_slot.var directly, ensuring it exists
            self.ensure_or_create(stack_slot.var, origin)
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
                    self.ensure_or_create(mapped, origin)
                } else {
                    // Ensure s.var exists
                    self.ensure_or_create(s.var, origin)
                };
                return result;
            }
        }

        // No defined value found. Try version stack as last resort.
        self.current_def(group)
            .unwrap_or_else(|| self.create_undefined_var(origin))
    }

    /// Ensures a variable with the given ID exists in the function, or creates a new one.
    ///
    /// If the variable exists, returns the same `var_id`. If it doesn't exist,
    /// creates a new variable via the allocator with the given origin and returns
    /// the newly allocated ID.
    fn ensure_or_create(&mut self, var_id: SsaVarId, origin: VariableOrigin) -> SsaVarId {
        if self.function.variable(var_id).is_some() {
            var_id
        } else {
            self.create_undefined_var(origin)
        }
    }

    /// Resolves a stack slot variable from a predecessor or idom exit stack.
    ///
    /// Given a stack slot's variable from an exit stack, resolves it through:
    /// 1. rename_map (already renamed)
    /// 2. load_origins → current_def (simulation variable from ldarg/ldloc)
    /// 3. Direct use (untracked stack variable)
    ///
    /// In all cases, ensures the resolved variable exists in the function.
    fn resolve_exit_stack_var(
        &mut self,
        stack_var: SsaVarId,
        origin: VariableOrigin,
        rename_map: &HashMap<SsaVarId, SsaVarId>,
    ) -> SsaVarId {
        if let Some(&already_renamed) = rename_map.get(&stack_var) {
            self.ensure_or_create(already_renamed, origin)
        } else if let Some(&load_origin) = self.load_origins.get(&stack_var) {
            if let Some(resolved) = self.current_def_for_origin(load_origin) {
                self.ensure_or_create(resolved, load_origin)
            } else {
                self.ensure_or_create(stack_var, origin)
            }
        } else {
            self.ensure_or_create(stack_var, origin)
        }
    }

    /// Resolves a use variable to its SSA-renamed counterpart.
    ///
    /// For Argument/Local origins, uses current_def from the version stack.
    /// For Stack origins, uses the rename_map.
    /// Ensures the resolved variable exists in the function.
    fn resolve_use(
        &mut self,
        use_var: SsaVarId,
        rename_map: &HashMap<SsaVarId, SsaVarId>,
    ) -> SsaVarId {
        if let Some(&mapped) = rename_map.get(&use_var) {
            self.resolve_mapped_use(mapped)
        } else {
            self.resolve_unmapped_use(use_var)
        }
    }

    /// Resolves a use variable that was found in the rename_map.
    fn resolve_mapped_use(&mut self, mapped: SsaVarId) -> SsaVarId {
        if let Some(var_info) = self.function.variable(mapped) {
            let origin = var_info.origin();
            match origin {
                VariableOrigin::Argument(_) | VariableOrigin::Local(_) => {
                    if let Some(resolved) = self.current_def_for_origin(origin) {
                        self.ensure_or_create(resolved, origin)
                    } else {
                        mapped
                    }
                }
                VariableOrigin::Phi => {
                    // Stack temps have Phi origin — resolve via rename group or
                    // var_stack_positions (simulation variables may not have groups yet)
                    let group = self.function.rename_group(mapped);
                    let group = if group != u32::MAX {
                        group
                    } else if let Some(&slot) = self.var_stack_positions.get(&mapped) {
                        self.stack_group(slot)
                    } else {
                        u32::MAX
                    };
                    if group != u32::MAX {
                        if let Some(resolved) = self.current_def(group) {
                            self.ensure_or_create(resolved, origin)
                        } else {
                            mapped
                        }
                    } else {
                        mapped
                    }
                }
            }
        } else {
            let origin = self.stack_slot_origin(0);
            self.ensure_or_create(mapped, origin)
        }
    }

    /// Resolves a use variable that was NOT found in the rename_map.
    fn resolve_unmapped_use(&mut self, use_var: SsaVarId) -> SsaVarId {
        if let Some(var_info) = self.function.variable(use_var) {
            let origin = var_info.origin();
            match origin {
                VariableOrigin::Argument(_) | VariableOrigin::Local(_) => {
                    if let Some(resolved) = self.current_def_for_origin(origin) {
                        self.ensure_or_create(resolved, origin)
                    } else {
                        use_var
                    }
                }
                VariableOrigin::Phi => {
                    // Stack temps have Phi origin — resolve via rename group or
                    // var_stack_positions (simulation variables may not have groups yet)
                    let group = self.function.rename_group(use_var);
                    let group = if group != u32::MAX {
                        group
                    } else if let Some(&slot) = self.var_stack_positions.get(&use_var) {
                        self.stack_group(slot)
                    } else {
                        u32::MAX
                    };
                    if group != u32::MAX {
                        if let Some(resolved) = self.current_def(group) {
                            self.ensure_or_create(resolved, origin)
                        } else {
                            use_var
                        }
                    } else {
                        use_var
                    }
                }
            }
        } else if let Some(&origin) = self.load_origins.get(&use_var) {
            if let Some(resolved) = self.current_def_for_origin(origin) {
                self.ensure_or_create(resolved, origin)
            } else {
                self.ensure_or_create(use_var, origin)
            }
        } else {
            self.ensure_or_create(use_var, self.stack_slot_origin(0))
        }
    }

    /// Resolves an entry stack slot to its reaching definition.
    ///
    /// For Stack origins, tries (in order):
    /// 1. Predecessor exit stacks
    /// 2. Immediate dominator exit stack
    /// 3. current_def from version stack
    ///
    /// Returns `None` if all resolution strategies fail.
    fn resolve_entry_stack_slot(
        &mut self,
        block_idx: usize,
        slot: usize,
        origin: VariableOrigin,
        idom_exit_stack: &Option<Vec<StackSlot>>,
        rename_map: &HashMap<SsaVarId, SsaVarId>,
    ) -> Option<SsaVarId> {
        // Try direct predecessors first (most accurate for stack values)
        for pred_id in self.cfg.predecessors(NodeId::new(block_idx)) {
            if let Some(pred_exit) = self.exit_stacks.get(&pred_id.index()) {
                if let Some(stack_slot) = pred_exit.get(slot) {
                    let resolved = self.resolve_exit_stack_var(stack_slot.var, origin, rename_map);
                    return Some(resolved);
                }
            }
        }

        // Fall back to immediate dominator's exit stack
        if let Some(ref idom_exit) = idom_exit_stack {
            if let Some(stack_slot) = idom_exit.get(slot) {
                let resolved = self.resolve_exit_stack_var(stack_slot.var, origin, rename_map);
                return Some(resolved);
            }
        }

        // Last resort: current_def via group (may be stale but better than nothing)
        // For stack origins, use the stack group
        let group = self.stack_group(slot);
        self.current_def(group)
    }

    /// Iteratively renames variables in a block and its dominated children.
    ///
    /// Uses an explicit work stack instead of recursion to avoid stack overflow
    /// on deeply nested dominator trees (common in obfuscated code).
    fn rename_block(
        &mut self,
        entry_block_idx: usize,
        dom_tree: &DominatorTree,
        rename_map: &mut HashMap<SsaVarId, SsaVarId>,
    ) -> Result<()> {
        // Work stack: Enter processes a block, Exit pops its version stack entries
        enum RenameAction {
            Enter(usize),
            Exit(HashMap<u32, usize>),
        }

        let mut work_stack = vec![RenameAction::Enter(entry_block_idx)];

        while let Some(action) = work_stack.pop() {
            match action {
                RenameAction::Exit(pushed_counts) => {
                    // Pop pushed definitions from version stacks
                    for (group, count) in pushed_counts {
                        if let Some(stack) = self.version_stacks.get_mut(&group) {
                            for _ in 0..count {
                                stack.pop();
                            }
                        }
                    }
                }
                RenameAction::Enter(block_idx) => {
                    let pushed_counts =
                        self.rename_block_process(block_idx, dom_tree, rename_map)?;

                    // Schedule exit (pop) BEFORE children so it runs AFTER children
                    // (work_stack is LIFO: last pushed = first processed)
                    let children: Vec<_> = dom_tree.children(NodeId::new(block_idx)).to_vec();

                    // Push exit action first (will be processed after all children)
                    work_stack.push(RenameAction::Exit(pushed_counts));

                    // Push children in reverse order so they're processed in forward order
                    for child in children.into_iter().rev() {
                        work_stack.push(RenameAction::Enter(child.index()));
                    }
                }
            }
        }

        Ok(())
    }

    /// Processes a single block during rename: phi nodes, entry stack, instructions,
    /// and successor phi operands. Returns the pushed_counts for version stack cleanup.
    fn rename_block_process(
        &mut self,
        block_idx: usize,
        dom_tree: &DominatorTree,
        rename_map: &mut HashMap<SsaVarId, SsaVarId>,
    ) -> Result<HashMap<u32, usize>> {
        let mut pushed_counts: HashMap<u32, usize> = HashMap::new();

        // Step 1: Process phi nodes - they define new versions
        let phi_count = self
            .function
            .block(block_idx)
            .map_or(0, SsaBlock::phi_count);

        let entry_stack = self.entry_stacks.get(&block_idx).cloned();
        let mut slots_with_phis: HashSet<u32> = HashSet::new();

        for phi_idx in 0..phi_count {
            if let Some(block) = self.function.block(block_idx) {
                if let Some(phi) = block.phi(phi_idx) {
                    let origin = phi.origin();
                    // Determine group from phi result's rename_group (set during phi placement)
                    let group = self.function.rename_group(phi.result());
                    let group = if group == u32::MAX {
                        // Fallback: determine group from origin
                        match origin {
                            VariableOrigin::Argument(idx) => self.arg_group(idx),
                            VariableOrigin::Local(idx) => self.local_group(idx),
                            VariableOrigin::Phi => {
                                // Stack phi — find slot from entry stack
                                self.stack_group(0)
                            }
                        }
                    } else {
                        group
                    };
                    // Phi type starts Unknown, resolved by resolve_phi_types() after rename
                    let new_var = self.new_def(origin, group, block_idx, None, SsaType::Unknown);
                    *pushed_counts.entry(group).or_insert(0) += 1;

                    if let Some(slot) = self.stack_slot_from_group(group) {
                        #[allow(clippy::cast_possible_truncation)]
                        slots_with_phis.insert(slot as u32);
                        if let Some(ref entry) = entry_stack {
                            if let Some(&placeholder) = entry.get(slot) {
                                rename_map.insert(placeholder, new_var);
                            }
                        }
                    }

                    if let Some(block) = self.function.block_mut(block_idx) {
                        if let Some(phi) = block.phi_mut(phi_idx) {
                            phi.set_result(new_var);
                        }
                    }
                }
            }
        }

        // Map entry stack slots without PHIs to reaching definitions.
        // For Stack groups, prefer predecessor exit stacks over current_def.
        let idom = dom_tree.immediate_dominator(NodeId::new(block_idx));
        let idom_exit_stack = idom.and_then(|d| self.exit_stacks.get(&d.index()).cloned());

        if let Some(ref entry) = entry_stack {
            for (slot, &placeholder) in entry.iter().enumerate() {
                #[allow(clippy::cast_possible_truncation)]
                let slot_u32 = slot as u32;
                if slots_with_phis.contains(&slot_u32) {
                    continue;
                }
                let origin = self.stack_slot_origin(slot);

                // Stack-derived locals: prefer predecessor exit stacks over current_def
                if let Some(resolved) = self.resolve_entry_stack_slot(
                    block_idx,
                    slot,
                    origin,
                    &idom_exit_stack,
                    rename_map,
                ) {
                    rename_map.insert(placeholder, resolved);
                    // Also push to version stack so that resolve_mapped_use (which
                    // checks current_def for the group) finds the correct reaching
                    // definition. Without this, handler blocks processed via BFS
                    // have stale version stacks (the predecessor's push was already
                    // popped by the Exit action), causing resolve_mapped_use to
                    // return the wrong variable.
                    let group = self.stack_group(slot);
                    self.version_stacks
                        .entry(group)
                        .or_default()
                        .push((0, resolved));
                    *pushed_counts.entry(group).or_insert(0) += 1;
                } else {
                    self.try_map_from_predecessors(block_idx, slot, placeholder, rename_map);
                }
            }
        }

        // Step 2: Process instructions - update uses and create new defs
        let instr_count = self
            .function
            .block(block_idx)
            .map_or(0, SsaBlock::instruction_count);

        for instr_idx in 0..instr_count {
            let instr_info = self.function.block(block_idx).and_then(|b| {
                b.instruction(instr_idx).map(|instr| {
                    // Detect LoadLocal/LoadArg for direct resolution to
                    // reaching definitions (avoids leaving unresolved
                    // memory-access ops that no optimisation pass can handle).
                    let load_target = match instr.op() {
                        SsaOp::LoadArg { arg_index, .. } => {
                            Some(VariableOrigin::Argument(*arg_index))
                        }
                        SsaOp::LoadLocal { local_index, .. } => {
                            Some(VariableOrigin::Local(*local_index))
                        }
                        _ => None,
                    };
                    (
                        instr.original().clone(),
                        instr.uses(),
                        instr.def(),
                        load_target,
                    )
                })
            });

            if let Some((cil_instr, uses, old_def, mut load_target)) = instr_info {
                // Skip resolution for address-taken locals/args: they may be
                // modified through pointers, so the reaching definition is
                // unsound.
                if let Some(ref origin) = load_target {
                    let group = match origin {
                        VariableOrigin::Argument(idx) => self.arg_group(*idx),
                        VariableOrigin::Local(idx) => self.local_group(*idx),
                        _ => u32::MAX,
                    };
                    if self.address_taken.contains(&group) {
                        load_target = None;
                    }
                }
                let mut renamed_uses = Vec::with_capacity(uses.len());
                for &use_var in &uses {
                    renamed_uses.push(self.resolve_use(use_var, rename_map));
                }

                for &use_var in &renamed_uses {
                    let use_site = UseSite::instruction(block_idx, instr_idx);
                    self.record_use(use_var, use_site);
                }

                if renamed_uses != uses {
                    if let Some(block) = self.function.block_mut(block_idx) {
                        if let Some(instr) = block.instruction_mut(instr_idx) {
                            let op = instr.op_mut();
                            for (old_use, &new_use) in uses.iter().zip(renamed_uses.iter()) {
                                if *old_use != new_use {
                                    op.replace_uses(*old_use, new_use);
                                }
                            }
                        }
                    }
                }

                // LoadLocal/LoadArg: convert to a Copy from the reaching definition
                // to a new stack-temp variable. This preserves an explicit bridge
                // between the local/arg group and the stack-temp group so that
                // rebuild_ssa (which operates per-group) can correctly recreate
                // the data flow across groups.
                if let (Some(sim_var), Some(target_origin)) = (old_def, load_target) {
                    let target_group = match target_origin {
                        VariableOrigin::Argument(idx) => self.arg_group(idx),
                        VariableOrigin::Local(idx) => self.local_group(idx),
                        _ => u32::MAX,
                    };
                    if let Some(reaching_def) = self.current_def(target_group) {
                        // Create a new stack-temp variable for the Copy dest
                        let slot = self.var_stack_positions.get(&sim_var).copied().unwrap_or(0);
                        let origin = self.stack_slot_origin(slot);
                        let dest_group = self.stack_group(slot);
                        let var_type = self.type_for_origin(target_origin);
                        let new_var =
                            self.new_def(origin, dest_group, block_idx, Some(instr_idx), var_type);
                        *pushed_counts.entry(dest_group).or_insert(0) += 1;

                        rename_map.insert(sim_var, new_var);

                        // Record the use of reaching_def by this Copy
                        let use_site = UseSite::instruction(block_idx, instr_idx);
                        self.record_use(reaching_def, use_site);

                        // Convert to Copy; the bridge instruction survives rebuild.
                        if let Some(block) = self.function.block_mut(block_idx) {
                            if let Some(instr) = block.instruction_mut(instr_idx) {
                                instr.set_op(SsaOp::Copy {
                                    dest: new_var,
                                    src: reaching_def,
                                });
                            }
                        }
                        continue;
                    }
                }

                let def_origin = Self::infer_origin(&cil_instr)?;

                if let Some(sim_var) = old_def {
                    let new_var = if let Some(origin) = def_origin {
                        let group = match origin {
                            VariableOrigin::Argument(idx) => self.arg_group(idx),
                            VariableOrigin::Local(idx) => self.local_group(idx),
                            VariableOrigin::Phi => u32::MAX, // shouldn't happen for infer_origin
                        };
                        let var_type = self.type_for_origin(origin);
                        let v = self.new_def(origin, group, block_idx, Some(instr_idx), var_type);
                        *pushed_counts.entry(group).or_insert(0) += 1;
                        v
                    } else {
                        // Use the stack depth position recorded during simulation,
                        // NOT sim_var.index() which is a globally unique ID.
                        // This ensures the group matches the PHI group at successor
                        // blocks (placed by place_stack_phi_nodes with stack_group).
                        let slot = self.var_stack_positions.get(&sim_var).copied().unwrap_or(0);
                        let origin = self.stack_slot_origin(slot);
                        let group = self.stack_group(slot);
                        let var_type = self.infer_instruction_result_type(block_idx, instr_idx);
                        let v = self.new_def(origin, group, block_idx, Some(instr_idx), var_type);
                        *pushed_counts.entry(group).or_insert(0) += 1;
                        v
                    };

                    rename_map.insert(sim_var, new_var);

                    if let Some(block) = self.function.block_mut(block_idx) {
                        if let Some(instr) = block.instruction_mut(instr_idx) {
                            instr.op_mut().set_dest(new_var);
                        }
                    }
                }

                if let Some(&store_target) = self.indirect_stores.get(&(block_idx, instr_idx)) {
                    let store_group = match store_target {
                        VariableOrigin::Argument(idx) => self.arg_group(idx),
                        VariableOrigin::Local(idx) => self.local_group(idx),
                        VariableOrigin::Phi => u32::MAX,
                    };
                    let var_type = self.type_for_origin(store_target);
                    let _new_version = self.new_def(
                        store_target,
                        store_group,
                        block_idx,
                        Some(instr_idx),
                        var_type,
                    );
                    *pushed_counts.entry(store_group).or_insert(0) += 1;
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
                let (phi_result, phi_group) =
                    match self.function.block(succ_idx).and_then(|b| b.phi(phi_idx)) {
                        Some(phi) => {
                            let mut group = self.function.rename_group(phi.result());
                            // If the phi result hasn't been renamed yet (still a
                            // placeholder from phi placement), determine the group
                            // from the phi's origin — same fallback as Step 1.
                            if group == u32::MAX {
                                group = match phi.origin() {
                                    VariableOrigin::Argument(idx) => self.arg_group(idx),
                                    VariableOrigin::Local(idx) => self.local_group(idx),
                                    VariableOrigin::Phi => u32::MAX,
                                };
                            }
                            (phi.result(), group)
                        }
                        None => continue,
                    };

                let reaching_def = if let Some(slot) = self.stack_slot_from_group(phi_group) {
                    #[allow(clippy::cast_possible_truncation)]
                    self.resolve_stack_phi_operand(
                        slot as u32,
                        phi_result,
                        exit_stack_enhanced.as_ref(),
                        rename_map,
                    )
                } else if phi_group != u32::MAX {
                    let origin = self.origin_for_group(phi_group);
                    self.current_def(phi_group)
                        .unwrap_or_else(|| self.create_undefined_var(origin))
                } else {
                    self.create_undefined_var(VariableOrigin::Phi)
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

        Ok(pushed_counts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        assembly::{decode_blocks, InstructionAssembler},
        test::TestTypeProvider,
    };

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
        let ssa = SsaConverter::build(&cfg, 2, 0, &TestTypeProvider::new(2, 0))
            .expect("SSA construction failed");

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
        let ssa = SsaConverter::build(&cfg, 1, 1, &TestTypeProvider::new(1, 1))
            .expect("SSA construction failed");

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
        let ssa = SsaConverter::build(&cfg, 1, 0, &TestTypeProvider::new(1, 0))
            .expect("SSA construction failed");

        // Should have 3 blocks: entry, then, else
        assert_eq!(ssa.block_count(), 3);

        // No phi nodes should be needed (no merge point)
        assert_eq!(ssa.phi_count(), 0);
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
        let ssa = SsaConverter::build(&cfg, 1, 1, &TestTypeProvider::new(1, 1))
            .expect("SSA construction failed");

        // Should have 4 blocks: entry, then, else, merge
        assert_eq!(ssa.block_count(), 4);

        // Should have a phi node in the merge block
        // (local0 is defined in both then and else branches)
        assert!(ssa.phi_count() > 0);
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
        let ssa = SsaConverter::build(&cfg, 1, 1, &TestTypeProvider::new(1, 1))
            .expect("SSA construction failed");

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
        let result = SsaConverter::build(&cfg, 0, 0, &TestTypeProvider::new(0, 0));
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
        let ssa = SsaConverter::build(&cfg, 0, 1, &TestTypeProvider::new(0, 1))
            .expect("SSA construction failed");

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
        let ssa = SsaConverter::build(&cfg, 1, 1, &TestTypeProvider::new(1, 1))
            .expect("SSA construction failed");

        // Find the merge block (block 3 in 0-indexed: entry=0, then=1, else=2, merge=3)
        // There should be a phi node for local0 in the merge block
        assert!(ssa.phi_count() > 0, "Expected phi nodes in merge block");

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
        let ssa = SsaConverter::build(&cfg, 0, 1, &TestTypeProvider::new(0, 1))
            .expect("SSA construction failed");

        // Loop header should have a phi node for local0 (merges initial value and loop value)
        assert!(
            ssa.phi_count() > 0,
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
        let ssa = SsaConverter::build(&cfg, 2, 1, &TestTypeProvider::new(2, 1))
            .expect("SSA construction failed");

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
        let ssa = SsaConverter::build(&cfg, 3, 0, &TestTypeProvider::new(3, 0))
            .expect("SSA construction failed");

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
        let ssa = SsaConverter::build(&cfg, 1, 0, &TestTypeProvider::new(1, 0))
            .expect("SSA construction failed");

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
        let ssa = SsaConverter::build(&cfg, 2, 1, &TestTypeProvider::new(2, 1))
            .expect("SSA construction failed");

        // Should have phi nodes at merge points
        assert!(ssa.phi_count() >= 1, "Expected phi nodes at merge points");

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
        let ssa = SsaConverter::build(&cfg, 1, 0, &TestTypeProvider::new(1, 0))
            .expect("SSA construction failed");

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
        let ssa = SsaConverter::build(&cfg, 1, 1, &TestTypeProvider::new(1, 1))
            .expect("SSA construction failed");

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
        let ssa = SsaConverter::build(&cfg, 0, 1, &TestTypeProvider::new(0, 1))
            .expect("SSA construction failed");

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
        let ssa = SsaConverter::build(&cfg, 1, 0, &TestTypeProvider::new(1, 0))
            .expect("SSA construction failed");

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
        let ssa = SsaConverter::build(&cfg, 0, 0, &TestTypeProvider::new(0, 0))
            .expect("SSA construction failed");

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
        let ssa = SsaConverter::build(&cfg, 0, 0, &TestTypeProvider::new(0, 0))
            .expect("SSA construction failed");

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
        let ssa = SsaConverter::build(&cfg, 1, 0, &TestTypeProvider::new(1, 0))
            .expect("SSA construction failed");

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
        let ssa = SsaConverter::build(&cfg, 0, 0, &TestTypeProvider::new(0, 0))
            .expect("SSA construction failed");

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
        let ssa = SsaConverter::build(&cfg, 0, 0, &TestTypeProvider::new(0, 0))
            .expect("SSA construction failed");

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
        let ssa = SsaConverter::build(&cfg, 0, 0, &TestTypeProvider::new(0, 0))
            .expect("SSA construction failed");

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
        let ssa = SsaConverter::build(&cfg, 0, 3, &TestTypeProvider::new(0, 3))
            .expect("SSA construction failed");

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
