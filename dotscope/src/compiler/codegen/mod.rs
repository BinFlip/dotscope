//! SSA to CIL code generation.
//!
//! This module provides the ability to convert SSA form back to CIL bytecode,
//! completing the roundtrip: CIL → SSA → (transformations) → CIL.
//!
//! # Architecture
//!
//! The code generator works in several phases:
//!
//! 1. **Register Allocation**: Maps SSA variables to CIL locals
//! 2. **Phi Elimination**: Converts phi nodes to moves at predecessor block ends
//! 3. **Block Ordering**: Orders blocks for efficient code layout
//! 4. **Instruction Selection**: Converts SSA ops to CIL instructions
//! 5. **Branch Resolution**: Resolves block indices to bytecode offsets
//!
//! # Module Organization
//!
//! - [`emitter`]: Low-level CIL instruction emission helpers
//!
//! # Optimizations
//!
//! The code generator performs several optimizations:
//!
//! - **Stack-based value forwarding**: Values that are immediately consumed by
//!   the next instruction are left on the stack instead of storing to locals.
//! - **Fallthrough optimization**: Jumps to the immediately following block are
//!   eliminated since execution falls through naturally.
//!
//! # Example
//!
//! ```rust,ignore
//! use dotscope::compiler::SsaCodeGenerator;
//!
//! let generator = SsaCodeGenerator::new();
//! let (bytecode, max_stack, locals) = generator.generate(&ssa_function)?;
//! ```

mod coalescing;
mod emitter;

#[cfg(test)]
mod tests;

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    hash::{Hash, Hasher},
};

/// Simple hash for generating unique field names for interned array data.
fn crc32_hash(data: &[u8]) -> u32 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    data.hash(&mut hasher);
    hasher.finish() as u32
}

use crate::{
    analysis::{
        CmpKind, ConstValue, SsaBlock, SsaFunction, SsaInstruction, SsaOp, SsaType, SsaVarId,
        SsaVariable, VariableOrigin,
    },
    assembly::{Immediate, InstructionEncoder, Operand},
    cilassembly::CilAssembly,
    compiler::codegen::coalescing::LocalCoalescer,
    metadata::{
        method::{ExceptionHandler, ExceptionHandlerFlags},
        signatures::{
            encode_field_signature, CustomModifiers, SignatureField, SignatureLocalVariable,
            TypeSignature,
        },
        tables::{
            ClassLayoutRaw, CodedIndex, CodedIndexType, FieldRaw, FieldRvaRaw, MemberRefRaw,
            NestedClassRaw, TableDataOwned, TableId, TypeDefRaw, TypeRefRaw,
        },
        token::Token,
    },
    Error, Result,
};

/// Output of [`SsaCodeGenerator::compile`] — everything needed to assemble a method body.
///
/// Contains the CIL bytecode, stack depth, local variable signatures, and remapped
/// exception handlers. This is the bridge between code generation and
/// [`MethodBodyBuilder::from_compilation`](crate::cilassembly::MethodBodyBuilder::from_compilation).
pub struct CompilationResult {
    /// CIL bytecode.
    pub bytecode: Vec<u8>,
    /// Maximum evaluation stack depth.
    pub max_stack: u16,
    /// Local variable signatures (already built with correct types).
    pub locals: Vec<SignatureLocalVariable>,
    /// Exception handlers with bytecode offsets (already remapped from SSA block IDs).
    pub exception_handlers: Vec<ExceptionHandler>,
}

/// Describes how an SSA variable maps to CIL storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum VarStorage {
    /// Variable is stored in an argument slot
    Arg(u16),
    /// Variable is stored in a local slot
    Local(u16),
    /// Variable is currently on the evaluation stack (not yet stored)
    Stack,
}

/// Pool of reusable temporary local slots.
///
/// Temporaries (e.g., for phi copies) are allocated from this pool and can be
/// released back for reuse by other temporaries of the same type.
/// Uses LIFO (stack) order for better cache locality.
#[derive(Debug, Default)]
struct TempPool {
    /// Free slots indexed by type
    free_by_type: HashMap<SsaType, Vec<u16>>,
}

impl TempPool {
    /// Try to allocate a slot from the pool for the given type.
    /// Returns `Some(slot)` if a free slot is available, `None` otherwise.
    fn try_allocate(&mut self, ty: &SsaType) -> Option<u16> {
        self.free_by_type.get_mut(ty).and_then(Vec::pop)
    }

    /// Release a slot back to the pool for the given type.
    /// Uses LIFO (push) for better cache locality when reallocated.
    fn release(&mut self, slot: u16, ty: SsaType) {
        self.free_by_type.entry(ty).or_default().push(slot);
    }

    /// Clear all pooled slots.
    fn clear(&mut self) {
        self.free_by_type.clear();
    }
}

/// SSA to CIL code generator.
///
/// Converts SSA form back to executable CIL bytecode with optimizations.
pub struct SsaCodeGenerator {
    /// Map from SSA variables to their storage location
    var_storage: BTreeMap<SsaVarId, VarStorage>,
    /// Next available local index
    next_local: u16,
    /// Map from block index to label name
    block_labels: BTreeMap<usize, String>,
    /// Variables that are currently on the stack (for optimization)
    stack_vars: Vec<SsaVarId>,
    /// Cache of interned decrypted strings (string content -> heap index)
    interned_strings: HashMap<String, u32>,
    /// Deferred constants: single-use constants that should be generated inline
    /// Maps variable ID to the constant value and whether it's been consumed
    deferred_constants: BTreeMap<SsaVarId, ConstValue>,
    /// Last loaded storage location for dup optimization.
    /// When we load the same location twice in a row, we can use `dup` instead.
    last_load: Option<VarStorage>,
    /// Global use counts for all variables across all blocks.
    /// Used to determine if a value needs to be stored to a local.
    global_use_counts: BTreeMap<SsaVarId, usize>,
    /// Types of allocated locals (local_idx -> SsaType).
    /// Used for generating correct local variable signatures.
    local_types: BTreeMap<u16, SsaType>,
    /// Map from original local index to compacted local index.
    /// Used for building local signatures with correct types.
    original_to_compacted: BTreeMap<u16, u16>,
    /// Map from block ID to its byte offset in the generated bytecode.
    /// Used for remapping exception handler offsets.
    block_offsets: BTreeMap<usize, u32>,
    /// Stack-local variables: variables that can live entirely on the evaluation
    /// stack without needing a local slot. These are single-use values defined
    /// and consumed within the same basic block before any control flow.
    stack_locals: BTreeSet<SsaVarId>,
    /// Pool of reusable temporary local slots for phi copies and other temps.
    temp_pool: TempPool,
    /// Locals that are actually used during code generation.
    /// Used to determine the true num_locals (eliminating unused locals).
    used_locals: BTreeSet<u16>,
    /// Cache of interned decrypted arrays — maps array data bytes to the
    /// FieldDef token and InitializeArray MemberRef token needed for codegen.
    interned_arrays: HashMap<Vec<u8>, InternedArrayInfo>,
    /// Tokens created during code generation that must be protected from cleanup.
    /// Includes FieldDef tokens for array initializer data and the parent TypeDef.
    protected_tokens: BTreeSet<Token>,
    /// TypeDef token of the parent type for interned array fields.
    /// Created lazily during `finalize_array_types()` — must be the LAST
    /// TypeDef appended so it owns all trailing fields via field_list ranges.
    array_parent_type: Option<Token>,
    /// RID of the first array data field, used as field_list for the parent TypeDef.
    array_first_field_rid: Option<u32>,
    /// Cache of data size → nested TypeDef token for `__StaticArrayInitTypeSize=N` types.
    /// Each unique array data size gets its own explicit-layout valuetype with
    /// ClassLayout.ClassSize = N, required by RuntimeHelpers.InitializeArray.
    array_size_types: BTreeMap<usize, Token>,
    /// Pre-computed set of all SSA variables that appear as phi operands.
    /// Used to quickly check whether a variable feeds into any phi node,
    /// avoiding repeated O(blocks × phis × operands) scans.
    all_phi_operands: BTreeSet<SsaVarId>,
    /// Pre-computed set of SSA variables used outside their defining block.
    /// A variable is in this set if any instruction in a block other than its
    /// definition block references it. Used to determine whether a value must
    /// be stored to a local (stack values don't persist across block boundaries).
    cross_block_uses: BTreeSet<SsaVarId>,
    /// Local indices accessed via LoadLocalAddr (address-taken locals).
    /// Const/Copy instructions that store to these locals must not be filtered
    /// out as dead, even if the dest variable has zero SSA uses — the runtime
    /// reads the actual memory location through the pointer.
    address_taken_locals: BTreeSet<u16>,
}

/// Information needed to emit a `RuntimeHelpers.InitializeArray` call for a decrypted array.
#[derive(Clone)]
struct InternedArrayInfo {
    /// Token of the FieldDef holding the FieldRVA data (for `ldtoken`).
    field_token: Token,
    /// Token of `RuntimeHelpers.InitializeArray` MemberRef (for `call`).
    initialize_array_token: Token,
}

/// Immutable context for block-level code generation.
///
/// Bundles references to block-specific data structures that are passed
/// unchanged through recursive code generation calls.
struct BlockCodegenContext<'a> {
    /// The SSA function being generated
    ssa: &'a SsaFunction,
    /// Operations in topological order for this block
    ops: &'a [&'a SsaOp],
    /// Pre-computed operands for each operation
    operands_cache: &'a [Vec<SsaVarId>],
    /// Maps variable IDs to their defining operation index
    def_map: &'a BTreeMap<SsaVarId, usize>,
    /// Current block index being generated
    current_block_idx: usize,
}

/// Work item for iterative code generation.
///
/// We use a multi-phase approach to ensure correct operand ordering:
/// - `Pending`: First visit - check if already generated
/// - `LoadOperand`: Load/generate a specific operand for an instruction
/// - `Emit`: All operands loaded, emit the operation
enum CodeGenWorkItem {
    /// First visit: check if already generated, then schedule operand loads
    Pending(usize),
    /// Load or generate a specific operand for instruction at idx
    /// (op_idx, operand_idx) - which operand of which instruction
    LoadOperand(usize, usize),
    /// All operands are on stack, emit the operation
    Emit(usize),
}

impl Default for SsaCodeGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl SsaCodeGenerator {
    /// Creates a new code generator.
    #[must_use]
    pub fn new() -> Self {
        Self {
            var_storage: BTreeMap::new(),
            next_local: 0,
            block_labels: BTreeMap::new(),
            stack_vars: Vec::new(),
            interned_strings: HashMap::new(),
            deferred_constants: BTreeMap::new(),
            last_load: None,
            global_use_counts: BTreeMap::new(),
            local_types: BTreeMap::new(),
            original_to_compacted: BTreeMap::new(),
            block_offsets: BTreeMap::new(),
            stack_locals: BTreeSet::new(),
            temp_pool: TempPool::default(),
            used_locals: BTreeSet::new(),
            interned_arrays: HashMap::new(),
            protected_tokens: BTreeSet::new(),
            array_parent_type: None,
            array_first_field_rid: None,
            array_size_types: BTreeMap::new(),
            all_phi_operands: BTreeSet::new(),
            cross_block_uses: BTreeSet::new(),
            address_taken_locals: BTreeSet::new(),
        }
    }

    /// Returns tokens created during code generation that must be protected
    /// from cleanup (FieldDef + TypeDef entries for array initializer data).
    #[must_use]
    pub fn protected_tokens(&self) -> &BTreeSet<Token> {
        &self.protected_tokens
    }

    /// Creates the parent `<PrivateImplementationDetails>` TypeDef and NestedClass
    /// entries for all size types created during array interning.
    ///
    /// MUST be called after all `compile()` calls and before the assembly is
    /// finalized. The parent TypeDef is created LAST so that its `field_list`
    /// range covers all the array data fields (ECMA-335 §II.22.37: a TypeDef
    /// owns all Field rows from its `field_list` to the next TypeDef's).
    pub fn finalize_array_types(&mut self, assembly: &mut CilAssembly) -> Result<()> {
        let Some(first_field_rid) = self.array_first_field_rid else {
            return Ok(()); // No array fields created
        };
        if self.array_parent_type.is_some() {
            return Ok(()); // Already finalized
        }

        let parent_token = Self::create_array_parent_type(assembly, first_field_rid)?;
        self.array_parent_type = Some(parent_token);
        self.protected_tokens.insert(parent_token);

        // Create NestedClass entries for each size type
        for &size_token in self.array_size_types.values() {
            assembly.table_row_add(
                TableId::NestedClass,
                TableDataOwned::NestedClass(NestedClassRaw {
                    rid: 0,
                    token: Token::new(0),
                    offset: 0,
                    nested_class: size_token.row(),
                    enclosing_class: parent_token.row(),
                }),
            )?;
        }

        Ok(())
    }

    /// Generates CIL bytecode from an SSA function.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to convert.
    ///
    /// # Returns
    ///
    /// A tuple of (bytecode, max_stack, num_locals).
    ///
    /// # Errors
    ///
    /// Returns an error if code generation fails due to invalid SSA or encoding issues.
    ///
    /// # Note
    ///
    /// This method does not support `DecryptedString` constants. If the SSA contains
    /// decrypted strings, use [`generate_with_assembly`](Self::generate_with_assembly) instead
    /// to properly intern strings into the assembly's #US heap.
    pub fn generate(&mut self, ssa: &SsaFunction) -> Result<(Vec<u8>, u16, u16)> {
        self.generate_internal(ssa, None)
    }

    /// Generates CIL bytecode from an SSA function with assembly mutation support.
    ///
    /// This method should be used when the SSA may contain `DecryptedString` constants
    /// from deobfuscation passes. The mutator is used to add decrypted strings to the
    /// assembly's #US heap and obtain proper indices for `ldstr` instructions.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to convert.
    /// * `mutator` - An assembly mutator for adding metadata entries (strings, etc.).
    ///
    /// # Returns
    ///
    /// A tuple of (bytecode, max_stack, num_locals).
    ///
    /// # Errors
    ///
    /// Returns an error if code generation fails due to invalid SSA, encoding issues,
    /// or problems adding strings to the heap.
    pub fn generate_with_assembly(
        &mut self,
        ssa: &SsaFunction,
        assembly: &mut CilAssembly,
    ) -> Result<(Vec<u8>, u16, u16)> {
        self.generate_internal(ssa, Some(assembly))
    }

    /// Generates CIL bytecode and builds a complete [`CompilationResult`].
    ///
    /// This is the high-level entry point that wraps [`generate_with_assembly`](Self::generate_with_assembly)
    /// and adds local variable signature building and exception handler remapping.
    /// The result contains everything needed for [`MethodBodyBuilder::from_compilation`](crate::cilassembly::MethodBodyBuilder::from_compilation)
    /// to assemble the final method body.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to convert.
    /// * `assembly` - An assembly mutator for adding metadata entries (strings, etc.).
    ///
    /// # Returns
    ///
    /// A [`CompilationResult`] with bytecode, max stack, local signatures, and exception handlers.
    ///
    /// # Errors
    ///
    /// Returns an error if code generation fails.
    pub fn compile(
        &mut self,
        ssa: &SsaFunction,
        assembly: &mut CilAssembly,
    ) -> Result<CompilationResult> {
        let (bytecode, max_stack, num_locals) = self.generate_with_assembly(ssa, assembly)?;

        // Build local variable signatures from codegen's compacted types.
        // Runtime-handle TypeRefs should have been pre-resolved via
        // [`set_handle_typerefs`] before this call; without it, locals
        // whose SSA type is a runtime handle fall back to `object` (the
        // analysis-crate default) and produce invalid CIL on `stloc`.
        let locals = self.build_local_signatures(ssa, num_locals)?;

        // Remap exception handlers using block offset mapping
        #[allow(clippy::cast_possible_truncation)]
        let exception_handlers = self.remap_exception_handlers(ssa, bytecode.len() as u32)?;

        Ok(CompilationResult {
            bytecode,
            max_stack,
            locals,
            exception_handlers,
        })
    }

    /// Builds local variable signatures from codegen state and original SSA types.
    ///
    /// # Errors
    ///
    /// Returns an error if a local variable's type cannot be determined from
    /// either the codegen state or the original SSA function.
    fn build_local_signatures(
        &self,
        ssa: &SsaFunction,
        num_locals: u16,
    ) -> Result<Vec<SignatureLocalVariable>> {
        let mut locals = Vec::with_capacity(num_locals as usize);
        for idx in 0..num_locals {
            // Priority: original_to_compacted (preserves exact original types for
            // LoadLocal/LoadLocalAddr referenced locals) > local_types (SSA-inferred).
            // This is important because LoadLocalAddr needs the exact declared type
            // (e.g., char for ldloca + char::ToString()).
            let local_type = if let Some(base) = self
                .original_to_compacted
                .iter()
                .find(|(_, &new)| new == idx)
                .and_then(|(&orig, _)| {
                    ssa.original_local_types()
                        .and_then(|types| types.get(orig as usize))
                        .map(|v| v.base.clone())
                }) {
                base
            } else if let Some(ssa_type) = self.local_types.get(&idx) {
                ssa_type.to_type_signature()
            } else {
                // Fallback: infer type from SSA variables mapped to this slot.
                // This handles cases where get_storage returns a raw Local index
                // for variables not tracked in local_types (e.g., x86-translated
                // methods where synthetic locals bypass type registration).
                self.infer_local_type_from_ssa(ssa, idx).ok_or_else(|| {
                    Error::CodegenFailed(format!(
                        "cannot determine type for local variable {idx}: \
                         not in codegen local_types and no original type mapping found"
                    ))
                })?
            };
            locals.push(SignatureLocalVariable {
                modifiers: CustomModifiers::default(),
                is_pinned: false,
                is_byref: false,
                base: local_type,
            });
        }
        Ok(locals)
    }

    /// Infers the type for a local slot by examining SSA variables.
    ///
    /// Looks for SSA variables whose storage maps to the given local slot
    /// (either through `var_storage` or through raw `Local(idx)` origin matching),
    /// and returns the first non-unknown type found.
    fn infer_local_type_from_ssa(
        &self,
        ssa: &SsaFunction,
        local_idx: u16,
    ) -> Option<TypeSignature> {
        let target_storage = VarStorage::Local(local_idx);

        // First check var_storage for variables explicitly mapped to this slot
        for (&var_id, &storage) in &self.var_storage {
            if storage == target_storage {
                if let Some(var) = ssa.variable(var_id) {
                    let var_type = var.var_type();
                    if !var_type.is_unknown() {
                        return Some(var_type.to_type_signature());
                    }
                }
            }
        }

        // Then check for variables with Local origin matching this index
        // (used when get_storage falls back to raw Local(idx))
        for var in ssa.variables() {
            if let VariableOrigin::Local(idx) = var.origin() {
                if idx == local_idx && !var.var_type().is_unknown() {
                    return Some(var.var_type().to_type_signature());
                }
            }
        }

        None
    }

    /// Remaps SSA exception handlers to bytecode offsets using block offset mapping.
    ///
    /// # Errors
    ///
    /// Returns an error if any exception handler has out-of-bounds offsets after remapping.
    fn remap_exception_handlers(
        &self,
        ssa: &SsaFunction,
        bytecode_len: u32,
    ) -> Result<Vec<ExceptionHandler>> {
        if !ssa.has_exception_handlers() {
            return Ok(Vec::new());
        }

        let mut handlers = Vec::new();

        for eh in ssa.exception_handlers() {
            let try_offset = eh
                .try_start_block
                .and_then(|b| self.block_offsets.get(&b).copied())
                .unwrap_or(eh.try_offset);

            let handler_offset = eh
                .handler_start_block
                .and_then(|b| self.block_offsets.get(&b).copied())
                .unwrap_or(eh.handler_offset);

            let try_end = eh
                .try_end_block
                .and_then(|b| self.block_offsets.get(&b).copied())
                .or_else(|| {
                    // If try_start has a valid mapping but try_end doesn't,
                    // the try region extends to the handler start
                    if eh.try_start_block.is_some() {
                        Some(handler_offset)
                    } else {
                        None
                    }
                })
                .unwrap_or(eh.try_offset.saturating_add(eh.try_length));

            let handler_end = eh
                .handler_end_block
                .and_then(|b| self.block_offsets.get(&b).copied())
                .or_else(|| {
                    // If handler_start has a valid mapping but handler_end doesn't,
                    // the handler extends to the end of bytecode
                    if eh.handler_start_block.is_some() {
                        Some(bytecode_len)
                    } else {
                        None
                    }
                })
                .unwrap_or(eh.handler_offset.saturating_add(eh.handler_length));

            let filter_offset = if eh.flags == ExceptionHandlerFlags::FILTER {
                eh.filter_start_block
                    .and_then(|b| self.block_offsets.get(&b).copied())
                    .unwrap_or(eh.class_token_or_filter)
            } else {
                eh.class_token_or_filter
            };

            // Drop handlers with empty try or handler regions. This happens
            // legitimately when optimization eliminates the guarded code — the
            // handler becomes unreachable and can be safely removed.
            if try_offset >= try_end || handler_offset >= handler_end {
                log::debug!(
                    "Dropping exception handler with empty region \
                     (try={try_offset}..{try_end}, handler={handler_offset}..{handler_end})"
                );
                continue;
            }

            // Validate offsets are within bytecode bounds. After the EH-aware
            // block linearizer, try blocks should always precede their handlers
            // and offsets should be in-bounds.
            if try_offset >= bytecode_len
                || handler_offset >= bytecode_len
                || try_end > bytecode_len
                || handler_end > bytecode_len
            {
                return Err(Error::CodegenFailed(format!(
                    "Exception handler offsets out of bounds \
                     (try={try_offset}..{try_end}, handler={handler_offset}..{handler_end}, \
                     bytecode_len={bytecode_len})"
                )));
            }

            handlers.push(ExceptionHandler {
                flags: eh.flags,
                try_offset,
                try_length: try_end.saturating_sub(try_offset),
                handler_offset,
                handler_length: handler_end.saturating_sub(handler_offset),
                handler: None,
                filter_offset,
            });
        }

        Ok(handlers)
    }

    /// Returns the types of any temporary locals allocated during code generation.
    ///
    /// These are locals that were created for PHI copy cycles or other codegen needs,
    /// beyond the original locals from the SSA function. The returned map contains
    /// (local_index -> type) pairs for these temporaries.
    ///
    /// This should be called after `generate_with_assembly` to get the types needed
    /// for generating a correct local variable signature.
    #[must_use]
    pub fn local_types(&self) -> &BTreeMap<u16, SsaType> {
        &self.local_types
    }

    /// Returns the mapping from original local indices to compacted indices.
    ///
    /// This should be called after `generate_with_assembly` to get the mapping needed
    /// for building local signatures with correct types from original SSA.
    #[must_use]
    pub fn original_local_mapping(&self) -> &BTreeMap<u16, u16> {
        &self.original_to_compacted
    }

    /// Returns the mapping from block IDs to their byte offsets in the generated code.
    ///
    /// This is used for remapping exception handler offsets. After code generation,
    /// the map contains each block's start offset in the new bytecode layout.
    ///
    /// This should be called after `generate_with_assembly` to get the offsets for
    /// exception handler remapping.
    #[must_use]
    pub fn block_offsets(&self) -> &BTreeMap<usize, u32> {
        &self.block_offsets
    }

    /// Internal generation method that optionally uses an assembly for string interning.
    fn generate_internal(
        &mut self,
        ssa: &SsaFunction,
        assembly: Option<&mut CilAssembly>,
    ) -> Result<(Vec<u8>, u16, u16)> {
        // Reset state
        self.var_storage.clear();
        self.next_local = 0;
        self.block_labels.clear();
        self.stack_vars.clear();
        self.interned_strings.clear();
        self.deferred_constants.clear();
        self.last_load = None;
        self.local_types.clear();
        self.original_to_compacted.clear();
        self.block_offsets.clear();
        self.stack_locals.clear();
        self.temp_pool.clear();
        self.used_locals.clear();
        self.interned_arrays.clear();
        self.all_phi_operands.clear();
        self.cross_block_uses.clear();
        self.address_taken_locals.clear();
        // Note: protected_tokens and array_parent_type are NOT cleared here.
        // They accumulate across multiple compile() calls within the same
        // codegen session, since all methods share the same parent TypeDef
        // and the field tokens must survive until cleanup.

        // Phase 0: Pre-intern all decrypted strings (if assembly provided)
        if let Some(assembly) = assembly {
            self.preintern_decrypted_values(ssa, assembly)?;
        }

        // Phase 1: Allocate storage for all SSA variables based on their origins
        self.allocate_storage(ssa)?;

        // Identify address-taken locals (accessed via LoadLocalAddr). Stores to
        // these locals must not be filtered out as "dead" by the Const/Copy
        // skip logic, because the runtime reads the actual memory location
        // through the pointer even though no SSA variable directly uses the
        // dest. Example: Monitor.Enter(obj, ref lockTaken) reads lockTaken
        // through the pointer and throws if it wasn't initialized to false.
        for block in ssa.blocks() {
            for instr in block.instructions() {
                if let SsaOp::LoadLocalAddr { local_index, .. } = instr.op() {
                    self.address_taken_locals.insert(*local_index);
                }
            }
        }

        // Pre-compute the actual definition block for each variable by scanning
        // instructions. This is more reliable than var.def_site() which can be
        // stale after SSA passes that move/merge blocks without updating metadata.
        let mut actual_def_block: BTreeMap<SsaVarId, usize> = BTreeMap::new();
        for block in ssa.blocks() {
            let block_id = block.id();
            for phi in block.phi_nodes() {
                actual_def_block.insert(phi.result(), block_id);
            }
            for instr in block.instructions() {
                if let Some(dest) = instr.def() {
                    actual_def_block.insert(dest, block_id);
                }
            }
        }

        // Pre-compute cross-block use set: variables used in blocks other than
        // where they are defined. These must be stored to locals because the CIL
        // evaluation stack doesn't persist across block boundaries.
        for block in ssa.blocks() {
            let block_id = block.id();
            for instr in block.instructions() {
                for &used_var in &instr.uses() {
                    if let Some(&def_block) = actual_def_block.get(&used_var) {
                        if def_block != block_id {
                            self.cross_block_uses.insert(used_var);
                        }
                    }
                }
            }
            // Phi operand uses always cross block boundaries
            for phi in block.phi_nodes() {
                for op in phi.operands() {
                    self.cross_block_uses.insert(op.value());
                }
            }
        }

        // Phase 2: Create block labels using actual block IDs (not sequential indices)
        for block in ssa.blocks() {
            let block_id = block.id();
            self.block_labels
                .insert(block_id, format!("block_{block_id}"));
        }
        // Also collect all branch targets and create labels for them
        self.collect_branch_targets(ssa);

        // Phase 3: Generate code
        let mut encoder = InstructionEncoder::new();

        // Set expected stack depth for exception handler entry blocks.
        // Catch and filter handlers start with the exception object already on the stack.
        for handler in ssa.exception_handlers() {
            // Catch handler entry: exception object is on the stack (depth 1)
            if let Some(handler_block) = handler.handler_start_block {
                if handler.flags == ExceptionHandlerFlags::EXCEPTION
                    || handler.flags == ExceptionHandlerFlags::FILTER
                {
                    if let Some(label) = self.block_labels.get(&handler_block) {
                        encoder.set_label_stack_depth(label, 1);
                    }
                }
            }
            // Filter block entry: exception object is on the stack (depth 1)
            if let Some(filter_block) = handler.filter_start_block {
                if handler.flags == ExceptionHandlerFlags::FILTER {
                    if let Some(label) = self.block_labels.get(&filter_block) {
                        encoder.set_label_stack_depth(label, 1);
                    }
                }
            }
        }

        // Collect branch targets - blocks that are referenced by some branch instruction
        let branch_targets: BTreeSet<usize> = self.block_labels.keys().copied().collect();

        // Include blocks that have ops OR are branch targets (even if they only have
        // undecomposed instructions). Blocks that are branch targets must be included
        // so their labels can be defined.
        let blocks_to_include: BTreeSet<usize> = ssa
            .blocks()
            .iter()
            .filter(|b| !b.instructions().is_empty() || branch_targets.contains(&b.id()))
            .map(SsaBlock::id)
            .collect();

        // Compute optimal block layout to minimize unnecessary branches.
        // This reorders blocks so that fall-through paths don't need explicit jumps.
        let block_ids = Self::compute_block_layout(ssa, &blocks_to_include);
        let blocks_to_generate: Vec<_> = block_ids.iter().filter_map(|&id| ssa.block(id)).collect();

        for (idx, block) in blocks_to_generate.iter().enumerate() {
            // Record block start offset for exception handler remapping
            let pos_before = encoder.current_position();
            self.block_offsets.insert(block.id(), pos_before);

            let next_block_idx = block_ids.get(idx.saturating_add(1)).copied();
            self.generate_block(&mut encoder, ssa, block, block.id(), next_block_idx)?;
        }

        // Phase 4: Finalize and resolve labels
        let (bytecode, max_stack, final_label_positions) = encoder.finalize()?;

        // Phase 5: Update block_offsets with final positions (after branch optimization)
        // The branch optimizer in finalize() may shrink branches, changing positions.
        // We need to use the final label positions to get accurate block offsets.
        for (label, position) in &final_label_positions {
            if let Some(block_id_str) = label.strip_prefix("block_") {
                if let Ok(block_id) = block_id_str.parse::<usize>() {
                    self.block_offsets.insert(block_id, *position);
                }
            }
        }

        // Calculate actual num_locals based on locals that were actually used.
        // This eliminates unused locals that were pre-allocated but never accessed.
        let num_locals = if self.used_locals.is_empty() {
            0
        } else {
            // We need max_index + 1 because local indices are 0-based
            self.used_locals
                .iter()
                .max()
                .copied()
                .unwrap_or(0)
                .saturating_add(1)
        };
        Ok((bytecode, max_stack, num_locals))
    }

    /// Pre-interns all decrypted values in the SSA into the assembly's metadata.
    ///
    /// - `DecryptedString`: added to the #US heap for `ldstr` emission
    /// - `DecryptedArray`: creates FieldRVA + FieldDef entries for
    ///   `RuntimeHelpers.InitializeArray` emission (compact, O(1) instructions)
    fn preintern_decrypted_values(
        &mut self,
        ssa: &SsaFunction,
        assembly: &mut CilAssembly,
    ) -> Result<()> {
        for block in ssa.blocks() {
            for instr in block.instructions() {
                match instr.op() {
                    SsaOp::Const {
                        value: ConstValue::DecryptedString(s),
                        ..
                    } if !self.interned_strings.contains_key(s.as_ref()) => {
                        let change_ref = assembly.userstring_add(s)?;
                        self.interned_strings
                            .insert(s.to_string(), change_ref.placeholder());
                    }
                    SsaOp::Const {
                        value: ConstValue::DecryptedArray(arr),
                        ..
                    } if !self.interned_arrays.contains_key(&arr.data) => {
                        if let Some(info) = self.intern_array_data(
                            &arr.data,
                            arr.element_type_ref.token(),
                            arr.element_size,
                            assembly,
                        )? {
                            self.interned_arrays.insert(arr.data.clone(), info);
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    /// Creates FieldRVA + FieldDef metadata entries for a decrypted array,
    /// enabling compact `RuntimeHelpers.InitializeArray` emission.
    ///
    /// On the first call, creates a parent TypeDef (`<PrivateImplementationDetails>`)
    /// appended at the end of the TypeDef table. All subsequent fields are also
    /// appended, maintaining the ECMA-335 sequential TypeDef→Field ownership
    /// invariant (since it's the last TypeDef, its field range extends to the
    /// end of the Field table).
    ///
    /// Returns `None` if the assembly lacks `RuntimeHelpers.InitializeArray`.
    fn intern_array_data(
        &mut self,
        data: &[u8],
        _element_type_token: Token,
        _element_size: usize,
        assembly: &mut CilAssembly,
    ) -> Result<Option<InternedArrayInfo>> {
        // Find RuntimeHelpers.InitializeArray MemberRef from raw tables
        let init_array_token = Self::find_initialize_array_memberref(assembly);
        let Some(init_array_token) = init_array_token else {
            return Ok(None);
        };

        // Track first field RID — all array-related TypeDefs use this same value
        // for field_list to maintain the monotonic ordering invariant (ECMA-335).
        // Size types own [first..first) = nothing; the parent (created last)
        // owns [first..end] = all array data fields.
        if self.array_first_field_rid.is_none() {
            self.array_first_field_rid = Some(assembly.next_rid(TableId::Field)?);
        }

        // Choose field type: get or create a __StaticArrayInitTypeSize=N
        // nested valuetype with ClassLayout.ClassSize = data.len().
        // RuntimeHelpers.InitializeArray requires the field's type to have
        // explicit size matching the array's byte length.
        // Note: parent TypeDef is NOT created here — it's deferred to
        // finalize_array_types() so it's the LAST TypeDef, owning all fields.
        let field_sig_blob = self.get_or_create_array_size_type(data.len(), assembly)?;

        // Store the raw data as FieldRVA
        let placeholder_rva = assembly.store_field_data(data.to_vec());

        // Add field name to strings heap (use a generated name)
        let field_name =
            assembly.string_get_or_add(&format!("__array_init_{:08X}", crc32_hash(data)))?;

        // Create FieldDef row: static, assembly-visible, HasFieldRVA
        let field_ref = assembly.table_row_add(
            TableId::Field,
            TableDataOwned::Field(FieldRaw {
                rid: 0, // assigned by table_row_add
                token: Token::new(0),
                offset: 0,
                flags: 0x0010 | 0x0003 | 0x0100, // Static | Assembly | HasFieldRVA
                name: field_name.placeholder(),
                signature: field_sig_blob,
            }),
        )?;

        // Use the resolved token from the ChangeRef — table_row_add resolves it
        // immediately with the correct RID (original_count + insertion_order).
        let field_token = field_ref.token().ok_or_else(|| {
            Error::CodegenFailed("table_row_add should resolve the token immediately".into())
        })?;

        // Protect this field from cleanup deletion
        self.protected_tokens.insert(field_token);

        // Create FieldRVA row
        assembly.table_row_add(
            TableId::FieldRVA,
            TableDataOwned::FieldRVA(FieldRvaRaw {
                rid: 0,
                token: Token::new(0),
                offset: 0,
                rva: placeholder_rva,
                field: field_ref.placeholder(),
            }),
        )?;

        Ok(Some(InternedArrayInfo {
            field_token,
            initialize_array_token: init_array_token,
        }))
    }

    /// Creates a parent TypeDef for interned array fields.
    ///
    /// Appends a new `<PrivateImplementationDetails>` TypeDef at the end of the
    /// TypeDef table. Its `field_list` points to the next Field RID that will be
    /// assigned, and since it's the last TypeDef, its field range extends to the
    /// end of the Field table (covering all subsequently appended fields).
    fn create_array_parent_type(assembly: &mut CilAssembly, first_field_rid: u32) -> Result<Token> {
        let type_name = assembly.string_get_or_add("<PrivateImplementationDetails>")?;

        // field_list points to the first array data field. Since this TypeDef
        // is the LAST one appended, its field range extends to the end of the
        // Field table — covering all subsequently created array data fields.
        let next_field_rid = first_field_rid;

        // method_list: point past all existing methods (no methods in this type).
        let next_method_rid = assembly.next_rid(TableId::MethodDef)?;

        // ECMA-335 §II.22.37: non-interface types MUST have a non-null extends.
        // Find System.Object TypeRef for the base class.
        let extends = Self::find_system_object_typeref(assembly)
            .unwrap_or_else(|| CodedIndex::new(TableId::TypeDef, 0, CodedIndexType::TypeDefOrRef));

        // Sealed | BeforeFieldInit | AutoLayout | NotPublic
        let flags: u32 = 0x0010_0100;

        let type_ref = assembly.table_row_add(
            TableId::TypeDef,
            TableDataOwned::TypeDef(TypeDefRaw {
                rid: 0,
                token: Token::new(0),
                offset: 0,
                flags,
                type_name: type_name.placeholder(),
                type_namespace: 0,
                extends,
                field_list: next_field_rid,
                method_list: next_method_rid,
            }),
        )?;

        type_ref
            .token()
            .ok_or_else(|| Error::ModificationInvalid("Failed to resolve TypeDef token".into()))
    }

    /// Finds the `System.Object` TypeRef in the assembly's TypeRef table.
    fn find_system_object_typeref(assembly: &CilAssembly) -> Option<CodedIndex> {
        let view = assembly.view();
        let tables = view.tables()?;
        let strings = view.strings()?;
        let typeref_table = tables.table::<TypeRefRaw>()?;

        for row in typeref_table.iter() {
            let Ok(name) = strings.get(row.type_name as usize) else {
                continue;
            };
            let Ok(ns) = strings.get(row.type_namespace as usize) else {
                continue;
            };
            if name == "Object" && ns == "System" {
                return Some(CodedIndex::new(
                    TableId::TypeRef,
                    row.rid,
                    CodedIndexType::TypeDefOrRef,
                ));
            }
        }
        None
    }

    /// Finds the `RuntimeHelpers.InitializeArray` MemberRef token in the assembly.
    fn find_initialize_array_memberref(assembly: &CilAssembly) -> Option<Token> {
        let tables = assembly.view().tables()?;
        let strings = assembly.view().strings()?;
        let member_refs = tables.table::<MemberRefRaw>()?;
        for row in member_refs {
            if let Ok(name) = strings.get(row.name as usize) {
                if name == "InitializeArray" {
                    return Some(row.token);
                }
            }
        }
        None
    }

    /// Gets or creates a `__StaticArrayInitTypeSize=N` nested valuetype with
    /// `ClassLayout.ClassSize = size`. Returns the blob placeholder for a field
    /// signature referencing that type.
    ///
    /// `RuntimeHelpers.InitializeArray` requires the FieldDef's type to have an
    /// explicit size (via ClassLayout) matching the array's total byte length.
    /// Using primitive types (int8, int32, etc.) causes "Field not large enough
    /// to fill array" at runtime.
    fn get_or_create_array_size_type(
        &mut self,
        size: usize,
        assembly: &mut CilAssembly,
    ) -> Result<u32> {
        // For sizes that match primitive types, use primitives directly.
        // The C# compiler does this: int64 for 8 bytes, int32 for 4, etc.
        // Mono handles primitive FieldRVA types correctly, but may have issues
        // with small ClassLayout value types.
        let primitive = match size {
            1 => Some(TypeSignature::I1),
            2 => Some(TypeSignature::I2),
            4 => Some(TypeSignature::I4),
            8 => Some(TypeSignature::I8),
            _ => None,
        };
        if let Some(prim_type) = primitive {
            let sig = SignatureField {
                modifiers: Vec::new(),
                base: prim_type,
            };
            let sig_bytes = encode_field_signature(&sig)?;
            let blob_ref = assembly.blob_add(&sig_bytes)?;
            return Ok(blob_ref.placeholder());
        }

        // Reuse existing type for this size
        let type_token = if let Some(&cached) = self.array_size_types.get(&size) {
            cached
        } else {
            // Create new __StaticArrayInitTypeSize=N nested valuetype.
            // Note: NestedClass entries linking to the parent are deferred to
            // finalize_array_types() — the parent TypeDef must be created LAST
            // to own all fields via field_list range.
            let type_name =
                assembly.string_get_or_add(&format!("__StaticArrayInitTypeSize={size}"))?;

            // Find System.ValueType TypeRef for the extends field
            let extends = Self::find_system_valuetype_typeref(assembly).unwrap_or_else(|| {
                Self::find_system_object_typeref(assembly).unwrap_or_else(|| {
                    CodedIndex::new(TableId::TypeDef, 0, CodedIndexType::TypeDefOrRef)
                })
            });

            // field_list: use the SAME value as all other array types to maintain
            // the monotonic ordering invariant. Since size types own no fields,
            // their range [first..first) is empty. The parent type (created last)
            // will also use first_field_rid but own [first..end].
            let next_field_rid = self
                .array_first_field_rid
                .unwrap_or(assembly.next_rid(TableId::Field)?);
            let next_method_rid = assembly.next_rid(TableId::MethodDef)?;

            // ExplicitLayout (0x10) | Sealed (0x100) | NestedAssembly (0x05) | ANSI (0x00)
            let flags: u32 = 0x0000_0115;

            let type_ref = assembly.table_row_add(
                TableId::TypeDef,
                TableDataOwned::TypeDef(TypeDefRaw {
                    rid: 0,
                    token: Token::new(0),
                    offset: 0,
                    flags,
                    type_name: type_name.placeholder(),
                    type_namespace: 0,
                    extends,
                    field_list: next_field_rid,
                    method_list: next_method_rid,
                }),
            )?;

            let new_token = type_ref.token().ok_or_else(|| {
                Error::ModificationInvalid("Failed to resolve size type token".into())
            })?;

            // Add ClassLayout row: PackingSize=1, ClassSize=size
            assembly.table_row_add(
                TableId::ClassLayout,
                TableDataOwned::ClassLayout(ClassLayoutRaw {
                    rid: 0,
                    token: Token::new(0),
                    offset: 0,
                    packing_size: 1,
                    class_size: u32::try_from(size).unwrap_or(u32::MAX),
                    parent: type_ref.placeholder(),
                }),
            )?;

            self.protected_tokens.insert(new_token);
            self.array_size_types.insert(size, new_token);
            new_token
        };

        // Build field signature: FIELD VALUETYPE <type_token>
        let sig = SignatureField {
            modifiers: Vec::new(),
            base: TypeSignature::ValueType(type_token),
        };
        let sig_bytes = encode_field_signature(&sig)?;
        let blob_ref = assembly.blob_add(&sig_bytes)?;
        Ok(blob_ref.placeholder())
    }

    /// Finds the `System.ValueType` TypeRef in the assembly's TypeRef table.
    fn find_system_valuetype_typeref(assembly: &CilAssembly) -> Option<CodedIndex> {
        let view = assembly.view();
        let tables = view.tables()?;
        let strings = view.strings()?;
        let typeref_table = tables.table::<TypeRefRaw>()?;

        for row in typeref_table.iter() {
            let Ok(name) = strings.get(row.type_name as usize) else {
                continue;
            };
            let Ok(ns) = strings.get(row.type_namespace as usize) else {
                continue;
            };
            if name == "ValueType" && ns == "System" {
                return Some(CodedIndex::new(
                    TableId::TypeRef,
                    row.rid,
                    CodedIndexType::TypeDefOrRef,
                ));
            }
        }
        None
    }

    /// Collects all branch targets and ensures they have labels.
    fn collect_branch_targets(&mut self, ssa: &SsaFunction) {
        for block in ssa.blocks() {
            for instr in block.instructions() {
                match instr.op() {
                    SsaOp::Jump { target } => {
                        self.block_labels
                            .entry(*target)
                            .or_insert_with(|| format!("block_{target}"));
                    }
                    SsaOp::Branch {
                        true_target,
                        false_target,
                        ..
                    }
                    | SsaOp::BranchCmp {
                        true_target,
                        false_target,
                        ..
                    } => {
                        self.block_labels
                            .entry(*true_target)
                            .or_insert_with(|| format!("block_{true_target}"));
                        self.block_labels
                            .entry(*false_target)
                            .or_insert_with(|| format!("block_{false_target}"));
                    }
                    SsaOp::Switch {
                        targets, default, ..
                    } => {
                        for target in targets {
                            self.block_labels
                                .entry(*target)
                                .or_insert_with(|| format!("block_{target}"));
                        }
                        self.block_labels
                            .entry(*default)
                            .or_insert_with(|| format!("block_{default}"));
                    }
                    SsaOp::Leave { target } => {
                        self.block_labels
                            .entry(*target)
                            .or_insert_with(|| format!("block_{target}"));
                    }
                    _ => {}
                }
            }
        }
    }

    /// Computes optimal block layout to minimize unnecessary branches.
    ///
    /// This reorders blocks so that fall-through paths (where one block jumps
    /// unconditionally to another) don't require explicit branch instructions.
    /// Uses a greedy approach that follows the most common execution path.
    ///
    /// # Algorithm
    ///
    /// 1. Start at block 0 (entry point)
    /// 2. Follow each block's preferred successor (for Jump: the target;
    ///    for Branch/Switch: the first target; for others: none)
    /// 3. When a block has no unvisited successor, pick the next unvisited block
    /// 4. Continue until all blocks are placed
    fn compute_block_layout(ssa: &SsaFunction, blocks_to_include: &BTreeSet<usize>) -> Vec<usize> {
        // Get the preferred successor for a block (the one we'd like to fall through to)
        fn preferred_successor(
            ssa: &SsaFunction,
            block_id: usize,
            leave_targets: &BTreeSet<usize>,
        ) -> Option<usize> {
            let block = ssa.block(block_id)?;
            // Look at the terminator instruction
            for instr in block.instructions().iter().rev() {
                match instr.op() {
                    // For Leave/Return/Throw/Rethrow/EndFinally/EndFilter, no successors
                    SsaOp::Leave { .. }
                    | SsaOp::Return { .. }
                    | SsaOp::Throw { .. }
                    | SsaOp::Rethrow
                    | SsaOp::EndFinally
                    | SsaOp::EndFilter { .. } => {
                        return None;
                    }
                    // For unconditional jump, the target is the preferred successor
                    // unless it's a leave target (merge point)
                    SsaOp::Jump { target } => {
                        if !leave_targets.contains(target) {
                            return Some(*target);
                        }
                        return None;
                    }
                    // For branches, prefer the false branch (often the fall-through case)
                    SsaOp::Branch { false_target, .. } | SsaOp::BranchCmp { false_target, .. } => {
                        return Some(*false_target);
                    }
                    // For switch, prefer the default case
                    SsaOp::Switch { default, .. } => {
                        return Some(*default);
                    }
                    _ => {}
                }
            }
            None
        }

        if blocks_to_include.is_empty() {
            return Vec::new();
        }

        // Build EH ordering constraints: try blocks must be placed before their
        // handler blocks in the layout. Without this, the linearizer can place a
        // handler block before its try block, producing inverted byte offsets
        // (e.g. try=93..60) that violate ECMA-335 EH semantics.
        //
        // For each handler_start_block, collect all try_start_blocks that must
        // precede it (a handler block may serve multiple EH regions).
        let mut handler_requires_try: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        // Map try_start_block → handler_start_block for scheduling handlers
        // after their try bodies.
        let mut try_to_handler: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for eh in ssa.exception_handlers() {
            if let (Some(try_block), Some(handler_block)) =
                (eh.try_start_block, eh.handler_start_block)
            {
                handler_requires_try
                    .entry(handler_block)
                    .or_default()
                    .push(try_block);
                try_to_handler
                    .entry(try_block)
                    .or_default()
                    .push(handler_block);
            }
        }

        // Collect Leave targets - these are merge points that should come after handlers
        let leave_targets: BTreeSet<usize> = ssa
            .blocks()
            .iter()
            .filter_map(|b| {
                if let Some(SsaOp::Leave { target }) = b.terminator_op() {
                    Some(*target)
                } else {
                    None
                }
            })
            .collect();

        // Identify all blocks within EH-protected regions (both try bodies and
        // handlers). These blocks must be laid out contiguously within their
        // respective regions. We BFS from each start block, following INTERNAL
        // control flow only. Leave/EndFinally/EndFilter/Throw/Rethrow exit the
        // region, so we don't follow their targets.
        let mut eh_region_blocks: BTreeSet<usize> = BTreeSet::new();
        for eh in ssa.exception_handlers() {
            let starts: Vec<usize> = [eh.try_start_block, eh.handler_start_block]
                .into_iter()
                .flatten()
                .collect();
            for start in starts {
                let mut bfs_queue = vec![start];
                while let Some(b) = bfs_queue.pop() {
                    if !eh_region_blocks.insert(b) || !blocks_to_include.contains(&b) {
                        continue;
                    }
                    if let Some(block) = ssa.block(b) {
                        if let Some(term) = block.terminator_op() {
                            // Only follow internal control flow. Leave exits the
                            // try region, EndFinally/EndFilter exit the handler,
                            // and Throw/Rethrow/Return exit everything.
                            match term {
                                SsaOp::Jump { target } => {
                                    bfs_queue.push(*target);
                                }
                                SsaOp::Branch {
                                    true_target,
                                    false_target,
                                    ..
                                }
                                | SsaOp::BranchCmp {
                                    true_target,
                                    false_target,
                                    ..
                                } => {
                                    bfs_queue.push(*true_target);
                                    bfs_queue.push(*false_target);
                                }
                                SsaOp::Switch {
                                    targets, default, ..
                                } => {
                                    for &t in targets {
                                        bfs_queue.push(t);
                                    }
                                    bfs_queue.push(*default);
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }

        let mut layout = Vec::with_capacity(blocks_to_include.len());
        let mut visited = BTreeSet::new();

        // Ensures a block and any prerequisite try blocks are added to the
        // worklist. If the block is a handler, its try blocks are pushed after
        // it (LIFO: they'll be popped and processed first), enforcing the
        // ECMA-335 EH ordering constraint.
        let enqueue_with_eh_deps =
            |block_id: usize, worklist: &mut Vec<usize>, visited: &BTreeSet<usize>| {
                worklist.push(block_id);
                if let Some(required_try_blocks) = handler_requires_try.get(&block_id) {
                    for &try_block in required_try_blocks {
                        if blocks_to_include.contains(&try_block) && !visited.contains(&try_block) {
                            worklist.push(try_block);
                        }
                    }
                }
            };

        // Start with block 0 if it's in the set, otherwise pick the first available
        let start = if blocks_to_include.contains(&0) {
            0
        } else {
            *blocks_to_include.iter().min().unwrap_or(&0)
        };

        // Use a worklist to process blocks
        let mut worklist = vec![start];

        while layout.len() < blocks_to_include.len() {
            // Process the worklist
            while let Some(block_id) = worklist.pop() {
                if !blocks_to_include.contains(&block_id) || visited.contains(&block_id) {
                    continue;
                }

                visited.insert(block_id);
                layout.push(block_id);

                // For blocks within EH regions, enqueue ALL internal successors
                // (not just the preferred one). EH region blocks must be
                // contiguous. Only follow Jump/Branch/Switch — not Leave/
                // EndFinally/etc. which exit the region.
                if eh_region_blocks.contains(&block_id) {
                    if let Some(block) = ssa.block(block_id) {
                        if let Some(term) = block.terminator_op() {
                            let targets: Vec<usize> = match term {
                                SsaOp::Jump { target } => vec![*target],
                                SsaOp::Branch {
                                    true_target,
                                    false_target,
                                    ..
                                }
                                | SsaOp::BranchCmp {
                                    true_target,
                                    false_target,
                                    ..
                                } => vec![*true_target, *false_target],
                                SsaOp::Switch {
                                    targets, default, ..
                                } => {
                                    let mut t = targets.clone();
                                    t.push(*default);
                                    t
                                }
                                _ => vec![],
                            };
                            for target in targets {
                                if blocks_to_include.contains(&target) && !visited.contains(&target)
                                {
                                    worklist.push(target);
                                }
                            }
                        }
                    }
                } else {
                    // Normal blocks: follow preferred successor only
                    if let Some(succ) = preferred_successor(ssa, block_id, &leave_targets) {
                        if blocks_to_include.contains(&succ) && !visited.contains(&succ) {
                            enqueue_with_eh_deps(succ, &mut worklist, &visited);
                        }
                    }
                }
            }

            // If worklist is empty but we haven't visited all blocks,
            // pick blocks in an order that keeps try/handler pairs together.
            // ECMA-335 requires try_offset < handler_offset, and try_end is
            // typically the handler's start offset. If handlers are placed far
            // from their try blocks, the try region expands to cover unrelated
            // code, producing overlapping/nested EH regions.
            if layout.len() < blocks_to_include.len() {
                let next_unvisited = |pred: &dyn Fn(usize) -> bool| -> Option<usize> {
                    blocks_to_include
                        .iter()
                        .filter(|&&b| !visited.contains(&b) && pred(b))
                        .min()
                        .copied()
                };

                // 1. Handler blocks whose try_start is already visited.
                // These must be placed right after their try body so that
                // try_end (= handler start offset) doesn't span unrelated code.
                if let Some(block_id) = next_unvisited(&|b| {
                    handler_requires_try
                        .get(&b)
                        .is_some_and(|try_blocks| try_blocks.iter().all(|t| visited.contains(t)))
                }) {
                    worklist.push(block_id);
                    continue;
                }

                // 2. Leave targets (merge points between sequential EH regions).
                // These must come after handlers but before new try blocks so
                // that setup code between sequential try/finally pairs is placed
                // correctly (e.g., re-loading _syncLock between two lock blocks).
                if let Some(block_id) = next_unvisited(&|b| leave_targets.contains(&b)) {
                    worklist.push(block_id);
                    continue;
                }

                // 3. Try blocks whose handlers haven't been visited yet
                if let Some(block_id) =
                    next_unvisited(&|b| handler_requires_try.values().flatten().any(|&t| t == b))
                {
                    worklist.push(block_id);
                    continue;
                }

                // 4. Handler blocks (with EH dep enforcement)
                if let Some(block_id) = next_unvisited(&|b| handler_requires_try.contains_key(&b)) {
                    enqueue_with_eh_deps(block_id, &mut worklist, &visited);
                    continue;
                }

                // 5. Any remaining blocks
                if let Some(block_id) = next_unvisited(&|_| true) {
                    worklist.push(block_id);
                }
            }
        }

        layout
    }

    /// Allocates storage for all SSA variables using graph coloring.
    ///
    /// Arguments get mapped to their original argument slots (ldarg/starg).
    /// Stack temporaries and phi results are coalesced using an interference
    /// graph to minimize the number of local slots needed.
    ///
    /// Single-use constants are deferred and will be generated inline at their
    /// use site instead of being stored to a local.
    fn allocate_storage(&mut self, ssa: &SsaFunction) -> Result<()> {
        // Phase 1: Classify variables and run register allocation.
        let coalesced_slots = self.allocate_storage_classify(ssa)?;

        // Collect exception handler entry blocks for Phase 4.
        let handler_entry_blocks: BTreeSet<usize> = ssa
            .exception_handlers()
            .iter()
            .filter_map(|h| h.handler_start_block)
            .collect();

        // Phase 2: Pre-allocate all live phi results to local slots.
        self.allocate_phi_results(ssa, &coalesced_slots)?;

        // Phase 3: Allocate remaining variables (stack temps, synthetics, phi operands).
        self.allocate_remaining_variables(ssa, &coalesced_slots)?;

        // Phase 4: Fix handler entry phi storage so exception handler phi results
        // share the same local as their operands.
        self.fixup_handler_phi_storage(ssa, &handler_entry_blocks);

        // Phase 5: Compact local slots to eliminate gaps from coalescer assignments.
        self.compact_local_slots();

        Ok(())
    }

    /// Phase 1 of storage allocation: classify variables and run register allocation.
    ///
    /// Computes global use counts, identifies deferred constants and stack locals,
    /// runs the local coalescer, and maps arguments and local-origin variables to
    /// their storage slots. Returns the coalesced slot assignments for use in
    /// subsequent phases.
    fn allocate_storage_classify(&mut self, ssa: &SsaFunction) -> Result<BTreeMap<SsaVarId, u16>> {
        // First, compute global use counts and identify single-use constants.
        // This avoids storing constants to locals only to load them back.
        self.global_use_counts = Self::compute_variable_use_counts(ssa);

        // Pre-compute the set of all phi operands. This replaces per-variable
        // O(blocks * phis * operands) scans with a single upfront pass and O(1)
        // lookups during identify_deferred_constants and identify_stack_locals.
        self.all_phi_operands.clear();
        for block in ssa.blocks() {
            for phi in block.phi_nodes() {
                for operand in phi.operands() {
                    self.all_phi_operands.insert(operand.value());
                }
            }
        }

        self.identify_deferred_constants(ssa, &self.global_use_counts.clone());

        // Identify stack locals - variables that can live entirely on the eval stack.
        // These are single-use values defined and consumed in the same block before
        // any control flow, so they never need a local slot.
        self.stack_locals = self.identify_stack_locals(ssa);

        // Use register allocation for efficient local usage
        // Automatically selects graph coloring (≤500 vars) or linear scan (>500 vars)
        let coalescer = LocalCoalescer::build(ssa);
        let allocation = coalescer.allocate(ssa)?;

        // Map arguments to their original slots
        for var in ssa.variables() {
            if let VariableOrigin::Argument(idx) = var.origin() {
                self.var_storage.insert(var.id(), VarStorage::Arg(idx));
            }
        }

        // Apply the coalesced allocation for Local-origin variables.
        for (var_id, local_slot) in &allocation.var_to_local {
            if let Some(ssa_var) = ssa.variable(*var_id) {
                if matches!(ssa_var.origin(), VariableOrigin::Local(_))
                    && !self.var_storage.contains_key(var_id)
                    && !self.deferred_constants.contains_key(var_id)
                {
                    self.var_storage
                        .insert(*var_id, VarStorage::Local(*local_slot));
                }
            }
        }

        self.original_to_compacted
            .clone_from(&allocation.original_to_compacted);

        // Set next_local to count of compacted original Local-origin variables.
        // Phase 2/3 will bump this when using coalesced slots for other variables.
        #[allow(clippy::cast_possible_truncation)]
        {
            self.next_local = allocation.original_to_compacted.len() as u16;
        }

        Ok(allocation.var_to_local)
    }

    /// Phase 2 of storage allocation: pre-allocate all live phi results to locals.
    ///
    /// Ensures consistent stack behavior -- phi results are always in locals,
    /// never on the stack. Dead phi results (use_count == 0) are skipped.
    fn allocate_phi_results(
        &mut self,
        ssa: &SsaFunction,
        coalesced_slots: &BTreeMap<SsaVarId, u16>,
    ) -> Result<()> {
        for block in ssa.blocks() {
            for phi in block.phi_nodes() {
                let phi_result = phi.result();

                // Skip if already allocated (shouldn't happen, but be safe)
                if self.var_storage.contains_key(&phi_result) {
                    continue;
                }

                // Skip dead phi results (not used by any instructions)
                let use_count = self
                    .global_use_counts
                    .get(&phi_result)
                    .copied()
                    .unwrap_or(0);
                if use_count == 0 {
                    continue;
                }

                // Use the coalescer's slot if available, otherwise allocate fresh
                let local_idx = if let Some(&slot) = coalesced_slots.get(&phi_result) {
                    // Bump next_local past any coalesced slot to avoid conflicts
                    self.next_local = self.next_local.max(slot.saturating_add(1));
                    slot
                } else {
                    let idx = self.next_local;
                    self.next_local = self.next_local.saturating_add(1);
                    idx
                };
                self.var_storage
                    .insert(phi_result, VarStorage::Local(local_idx));

                // Record the type for the local variable signature.
                // Try phi result type first, then infer from operands.
                let phi_type = ssa
                    .variable(phi_result)
                    .map(SsaVariable::var_type)
                    .filter(|t| !t.is_unknown())
                    .cloned();

                let final_type = phi_type.or_else(|| {
                    let mut visited = BTreeSet::new();
                    visited.insert(phi_result); // prevent self-referential phi loops
                    for operand in phi.operands() {
                        if let Ok(ty) =
                            Self::infer_variable_type_inner(ssa, operand.value(), &mut visited)
                        {
                            return Some(ty);
                        }
                    }
                    None
                });

                let final_type = final_type.ok_or_else(|| {
                    Error::CodegenFailed(format!(
                        "cannot determine type for phi result {phi_result:?} \
                         (local {local_idx}): phi and all operands have unknown types"
                    ))
                })?;
                self.local_types.insert(local_idx, final_type);
            }
        }
        Ok(())
    }

    /// Phase 3 of storage allocation: allocate remaining variables.
    ///
    /// Handles phi-origin variables (stack temps, pass-created synthetics) and
    /// phi operands that belong to non-dead phi nodes. Phi operand uses are NOT
    /// counted in `global_use_counts`, so a variable used only as a phi operand
    /// would have use_count=0 but still needs storage for phi copy emission.
    fn allocate_remaining_variables(
        &mut self,
        ssa: &SsaFunction,
        coalesced_slots: &BTreeMap<SsaVarId, u16>,
    ) -> Result<()> {
        // First, collect all phi operands that need storage (belong to non-dead phi nodes)
        let mut phi_operands_needing_storage: BTreeSet<SsaVarId> = BTreeSet::new();
        for block in ssa.blocks() {
            for phi in block.phi_nodes() {
                let phi_result = phi.result();
                let use_count = self
                    .global_use_counts
                    .get(&phi_result)
                    .copied()
                    .unwrap_or(0);
                // Skip dead phi nodes
                if use_count == 0 {
                    continue;
                }
                // This phi node is live - its operands need storage
                for operand in phi.operands() {
                    phi_operands_needing_storage.insert(operand.value());
                }
            }
        }

        for var in ssa.variables() {
            let var_id = var.id();

            // Skip if already allocated
            if self.var_storage.contains_key(&var_id) {
                continue;
            }

            // Only handle non-Local, non-Argument variables here.
            // Local and Argument origins are handled in Phase 1.
            match var.origin() {
                VariableOrigin::Local(_) | VariableOrigin::Argument(_) => continue,
                _ => {} // Phi, Stack, Compiler origins
            }

            // Skip if it's a deferred constant
            if self.deferred_constants.contains_key(&var_id) {
                continue;
            }

            // Skip if it's a stack local (can live on eval stack)
            if self.stack_locals.contains(&var_id) {
                continue;
            }

            // Skip dead variables that are not phi operands
            let use_count = self.global_use_counts.get(&var_id).copied().unwrap_or(0);
            let is_phi_operand = phi_operands_needing_storage.contains(&var_id);
            if use_count == 0 && !is_phi_operand {
                continue;
            }

            // Skip variables with no definition AND unknown type. These are
            // runtime-injected values (e.g., exception objects pushed onto the
            // stack at handler entry blocks) that never need to be loaded from
            // storage — the codegen handles them specially (e.g., clearing Pop
            // operands). Variables with a known type but no definition may still
            // need storage (e.g., after SSA rebuild renaming).
            if var.var_type().is_unknown()
                && ssa.get_definition(var_id).is_none()
                && ssa.find_phi_defining(var_id).is_none()
            {
                continue;
            }

            // Use the coalescer's slot if available, otherwise allocate fresh
            let local_idx = if let Some(&slot) = coalesced_slots.get(&var_id) {
                // Bump next_local past any coalesced slot to avoid conflicts
                self.next_local = self.next_local.max(slot.saturating_add(1));
                slot
            } else {
                let idx = self.next_local;
                self.next_local = self.next_local.saturating_add(1);
                idx
            };
            self.var_storage
                .insert(var_id, VarStorage::Local(local_idx));

            // Record the type — try declared type first, then infer from definition
            let var_type = var.var_type();
            if var_type.is_unknown() {
                let inferred = Self::infer_variable_type(ssa, var_id)?;
                self.local_types.insert(local_idx, inferred);
            } else {
                self.local_types.insert(local_idx, var_type.clone());
            }
        }
        Ok(())
    }

    /// Phase 4 of storage allocation: fix handler entry phi storage.
    ///
    /// Exception dispatch preserves locals but doesn't execute phi copies.
    /// Phi results in exception handler entry blocks must share storage with
    /// their operands so the handler reads the same local the try block wrote to.
    fn fixup_handler_phi_storage(
        &mut self,
        ssa: &SsaFunction,
        handler_entry_blocks: &BTreeSet<usize>,
    ) {
        for (block_idx, block) in ssa.blocks().iter().enumerate() {
            if !handler_entry_blocks.contains(&block_idx) {
                continue;
            }
            for phi in block.phi_nodes() {
                let phi_result = phi.result();
                // Skip unallocated or dead phi results
                if !self.var_storage.contains_key(&phi_result) {
                    continue;
                }
                // Find an operand that has storage allocated
                if let Some(operand_storage) = phi
                    .operands()
                    .iter()
                    .find_map(|op| self.var_storage.get(&op.value()).copied())
                {
                    let current = self.var_storage.get(&phi_result).copied();
                    if current != Some(operand_storage) {
                        self.var_storage.insert(phi_result, operand_storage);
                    }
                }
            }
        }
    }

    /// Phase 5 of storage allocation: compact local slots.
    ///
    /// The coalescer may assign non-contiguous slots because it allocates for
    /// ALL variables, but codegen skips some (deferred constants, stack locals).
    /// This method remaps slots to be contiguous so `build_local_signatures`
    /// produces correct 0..num_locals with types for each.
    fn compact_local_slots(&mut self) {
        let mut used_slots: Vec<u16> = self
            .var_storage
            .values()
            .filter_map(|s| match s {
                VarStorage::Local(idx) => Some(*idx),
                _ => None,
            })
            .collect();
        // Also include slots from original_to_compacted. These are reserved for
        // LoadLocal/LoadLocalAddr-referenced locals that may not have SSA variables
        // in var_storage (their Local-origin variables were optimized away, but
        // the LoadLocal/LoadLocalAddr instructions still reference the slot).
        // Without this, slot compaction fills these "gaps" and Phi-origin variables
        // get remapped into reserved slots, overriding the original local types.
        used_slots.extend(self.original_to_compacted.values());
        used_slots.sort_unstable();
        used_slots.dedup();

        // Build remap: old slot → new contiguous slot
        let remap: BTreeMap<u16, u16> = used_slots
            .iter()
            .enumerate()
            .filter_map(|(new, &old)| {
                #[allow(clippy::cast_possible_truncation)]
                if old != new as u16 {
                    Some((old, new as u16))
                } else {
                    None
                }
            })
            .collect();

        if !remap.is_empty() {
            // Remap var_storage
            for storage in self.var_storage.values_mut() {
                if let VarStorage::Local(idx) = storage {
                    if let Some(&new_idx) = remap.get(idx) {
                        *idx = new_idx;
                    }
                }
            }

            // Remap local_types
            let old_types = std::mem::take(&mut self.local_types);
            for (old_idx, ty) in old_types {
                let new_idx = remap.get(&old_idx).copied().unwrap_or(old_idx);
                self.local_types.insert(new_idx, ty);
            }

            // Remap original_to_compacted
            for val in self.original_to_compacted.values_mut() {
                if let Some(&new_idx) = remap.get(val) {
                    *val = new_idx;
                }
            }

            #[allow(clippy::cast_possible_truncation)]
            {
                self.next_local = used_slots.len() as u16;
            }
        }
    }

    /// Computes use counts for all variables in the SSA function.
    ///
    /// Two-pass approach:
    /// 1. Count uses in instructions
    /// 2. For live phi nodes (result has instruction uses), count operand uses
    ///
    /// This ensures variables used only as phi operands get proper storage
    /// allocation and correct emit handling (cross-block stores, etc.).
    fn compute_variable_use_counts(ssa: &SsaFunction) -> BTreeMap<SsaVarId, usize> {
        let mut use_counts: BTreeMap<SsaVarId, usize> = BTreeMap::new();

        // Pass 1: Count instruction uses only
        for block in ssa.blocks() {
            for instr in block.instructions() {
                for var in instr.op().uses() {
                    let entry = use_counts.entry(var).or_insert(0);
                    *entry = entry.saturating_add(1);
                }
            }
        }

        // Pass 2: Transitively count phi operand uses. A phi node is "live" if its
        // result has uses (instruction uses or as an operand of another live phi).
        // We first collect all live phi results, then propagate through phi chains.
        //
        // This handles nested phi chains (e.g., nested if-else where an inner merge
        // phi feeds an outer merge phi). Without this, variables only used through
        // a chain of phi nodes would have use_count == 0, causing codegen to treat
        // them as dead and lose their values.
        let mut live_phis: BTreeSet<SsaVarId> = BTreeSet::new();

        // Seed: phi results that already have instruction uses
        for block in ssa.blocks() {
            for phi in block.phi_nodes() {
                if use_counts.get(&phi.result()).copied().unwrap_or(0) > 0 {
                    live_phis.insert(phi.result());
                }
            }
        }

        // Propagate: phi operands that are themselves phi results become live
        loop {
            let mut new_live = Vec::new();
            for block in ssa.blocks() {
                for phi in block.phi_nodes() {
                    if live_phis.contains(&phi.result()) {
                        for operand in phi.operands() {
                            let val = operand.value();
                            if !live_phis.contains(&val) {
                                // Check if this operand is itself a phi result
                                // (it will be counted as live in the next iteration)
                                new_live.push(val);
                            }
                        }
                    }
                }
            }

            if new_live.is_empty() {
                break;
            }
            for v in new_live {
                live_phis.insert(v);
            }
        }

        // Now count: for each live phi, count its operands as used
        for block in ssa.blocks() {
            for phi in block.phi_nodes() {
                if live_phis.contains(&phi.result()) {
                    for operand in phi.operands() {
                        let entry = use_counts.entry(operand.value()).or_insert(0);
                        *entry = entry.saturating_add(1);
                    }
                }
            }
        }

        use_counts
    }

    /// Identifies constants that are only used once and can be generated inline.
    fn identify_deferred_constants(
        &mut self,
        ssa: &SsaFunction,
        use_counts: &BTreeMap<SsaVarId, usize>,
    ) {
        for block in ssa.blocks() {
            for instr in block.instructions() {
                if let SsaOp::Const { dest, value } = instr.op() {
                    // Only defer if used exactly once and not used in phi nodes
                    // (phi operands need to be available at block boundaries).
                    // DecryptedArray is not deferrable because it emits multiple
                    // instructions (newarr + InitializeArray) that don't compose
                    // well with inline emission at use sites.
                    let uses = use_counts.get(dest).copied().unwrap_or(0);
                    let is_compound = matches!(value, ConstValue::DecryptedArray { .. });
                    if uses == 1 && !self.all_phi_operands.contains(dest) && !is_compound {
                        self.deferred_constants.insert(*dest, value.clone());
                    }
                }
            }
        }
    }

    /// Identifies variables that can live entirely on the evaluation stack.
    ///
    /// Stack locals are variables that meet ALL of these criteria:
    /// 1. Single definition
    /// 2. All uses in same block as definition
    /// 3. Not used as a phi operand (phi copies happen at block boundaries)
    /// 4. Uses are in straight-line code before any control flow
    /// 5. Value is consumed before any terminator
    ///
    /// These variables never need a local slot - they can stay on the eval stack.
    fn identify_stack_locals(&self, ssa: &SsaFunction) -> BTreeSet<SsaVarId> {
        let mut candidates = BTreeSet::new();

        for block in ssa.blocks() {
            let block_id = block.id();

            for instr in block.instructions() {
                // Only consider ops that produce a value
                if let Some(dest) = instr.op().dest() {
                    if self.can_be_stack_local(ssa, dest, block_id) {
                        candidates.insert(dest);
                    }
                }
            }
        }

        candidates
    }

    /// Checks if a variable can be a stack local (no local slot needed).
    fn can_be_stack_local(&self, ssa: &SsaFunction, var: SsaVarId, def_block: usize) -> bool {
        // Condition 1: Check use count (should be exactly 1 for stack-only)
        // Variables with 0 uses are dead and will be skipped anyway.
        // Variables with >1 uses might need the value multiple times.
        let use_count = self.global_use_counts.get(&var).copied().unwrap_or(0);
        if use_count != 1 {
            return false;
        }

        // Condition 2: Not used as a phi operand (phi copies happen at block boundaries)
        if self.all_phi_operands.contains(&var) {
            return false;
        }

        // Condition 3: The single use must be in the same block
        // Find the use site
        let Some(block) = ssa.blocks().iter().find(|b| b.id() == def_block) else {
            return false;
        };

        // Find the definition index and use index within the block
        let instrs = block.instructions();
        let mut def_idx: Option<usize> = None;
        let mut use_idx: Option<usize> = None;

        for (idx, instr) in instrs.iter().enumerate() {
            let op = instr.op();
            // Check if this is the definition
            if op.dest() == Some(var) {
                def_idx = Some(idx);
            }
            // Check if this uses our variable
            if op.uses().contains(&var) {
                use_idx = Some(idx);
            }
        }

        // Must have both def and use in this block
        let (Some(d_idx), Some(u_idx)) = (def_idx, use_idx) else {
            return false;
        };

        // Condition 4: Use must come after definition (should always be true in SSA)
        if u_idx <= d_idx {
            return false;
        }

        // Condition 5: Use must be IMMEDIATELY after def (no instructions between)
        // This is required because any instruction between def and use might push
        // values onto the stack, burying our value and making it inaccessible.
        // A more sophisticated analysis could check if intervening instructions
        // consume their values before our use, but that's complex and error-prone.
        if u_idx != d_idx.saturating_add(1) {
            return false;
        }

        // Note: We still check for terminators below, but with the immediate-use
        // requirement above, there can't be any terminators between def and use.

        // Condition 6: The use itself should not be a terminator operand
        // (terminators trigger spilling, so the value would be stored anyway)
        let Some(use_instr) = instrs.get(u_idx) else {
            return false;
        };
        if Self::is_terminator(use_instr.op()) {
            return false;
        }

        true
    }

    /// Gets the storage for an SSA variable, allocating a local if needed.
    ///
    /// # Errors
    ///
    /// Returns an error if a local must be allocated but its type cannot be determined.
    fn get_or_allocate_storage(&mut self, ssa: &SsaFunction, var: SsaVarId) -> Result<VarStorage> {
        if let Some(&storage) = self.var_storage.get(&var) {
            return Ok(storage);
        }

        // Stack locals never need a local slot - they're consumed before burial
        if self.stack_locals.contains(&var) {
            return Ok(VarStorage::Stack);
        }

        // Try to look up the variable's origin
        if let Some(ssa_var) = ssa.variable(var) {
            match ssa_var.origin() {
                VariableOrigin::Argument(idx) => {
                    let storage = VarStorage::Arg(idx);
                    self.var_storage.insert(var, storage);
                    return Ok(storage);
                }
                VariableOrigin::Local(original_idx) => {
                    // Use the compacted index from the coalescer's allocation
                    if let Some(&compacted_idx) = self.original_to_compacted.get(&original_idx) {
                        let storage = VarStorage::Local(compacted_idx);
                        self.var_storage.insert(var, storage);
                        // Record the type for the compacted slot
                        let var_type = ssa_var.var_type();
                        if !var_type.is_unknown() {
                            self.local_types.insert(compacted_idx, var_type.clone());
                        }
                        return Ok(storage);
                    }
                    // If not in the compacted mapping, fall through to allocate
                    // (this handles edge cases where a Local var wasn't seen during coalescing)
                }
                VariableOrigin::Phi => {
                    // Fall through to allocate a new local
                }
            }
        }

        // Default: allocate a new local
        let local = self.next_local;
        self.next_local = self.next_local.saturating_add(1);
        let storage = VarStorage::Local(local);
        self.var_storage.insert(var, storage);

        // Record the type of this newly allocated local so it gets included in the signature
        let var_type = ssa
            .variable(var)
            .map(|v| v.var_type().clone())
            .filter(|t| !t.is_unknown())
            .ok_or_else(|| {
                Error::CodegenFailed(format!(
                    "cannot determine type for variable {var:?} when allocating local {local}"
                ))
            })?;
        self.local_types.insert(local, var_type);

        Ok(storage)
    }

    /// Force-allocates storage for a variable that must have a real local/arg slot.
    ///
    /// Unlike `get_or_allocate_storage`, this method never returns `VarStorage::Stack`.
    /// It's used when a variable that was expected to stay on the stack needs to be
    /// stored to a local (e.g., when it gets buried by other values).
    ///
    /// # Errors
    ///
    /// Returns an error if the variable's type cannot be determined.
    fn force_allocate_storage(&mut self, ssa: &SsaFunction, var: SsaVarId) -> Result<VarStorage> {
        // Check existing storage first
        if let Some(&storage) = self.var_storage.get(&var) {
            if !matches!(storage, VarStorage::Stack) {
                return Ok(storage);
            }
            // Stack storage is not allowed - need to allocate a real slot
            // This can happen if the variable was previously identified as a stack_local
            // but now needs real storage due to being buried.
        }

        // Try to look up the variable's origin for arguments
        if let Some(ssa_var) = ssa.variable(var) {
            if let VariableOrigin::Argument(idx) = ssa_var.origin() {
                let storage = VarStorage::Arg(idx);
                self.var_storage.insert(var, storage);
                return Ok(storage);
            }
        }

        // Determine the type for this local:
        // 1. Try the variable's type from SSA
        // 2. Try to infer from the definition operation
        let var_type = Self::infer_variable_type(ssa, var)?;

        // Allocate a new local slot
        let local = self.next_local;
        self.next_local = self.next_local.saturating_add(1);
        let storage = VarStorage::Local(local);
        self.var_storage.insert(var, storage);

        // Also remove from stack_locals since it now has real storage
        self.stack_locals.remove(&var);

        // Record the type of this newly allocated local
        self.local_types.insert(local, var_type);

        Ok(storage)
    }

    /// Infers the type of a variable from SSA metadata and its definition.
    ///
    /// Delegates to `infer_variable_type_inner` with cycle detection.
    ///
    /// # Errors
    ///
    /// Returns an error if the type cannot be determined from either the SSA
    /// variable metadata or the defining operation.
    fn infer_variable_type(ssa: &SsaFunction, var: SsaVarId) -> Result<SsaType> {
        let mut visited = BTreeSet::new();
        Self::infer_variable_type_inner(ssa, var, &mut visited)
    }

    /// Recursive helper for type inference with cycle detection.
    ///
    /// Uses a priority chain:
    /// 1. Variable's declared type (set during construction/rebuild)
    /// 2. Defining instruction's result_type (from converter with TypeContext — most precise)
    /// 3. Defining op's structural infer_result_type() (for Const/Conv/etc.)
    /// 4. Copy/phi chain tracing
    /// 5. Error if no type can be determined (no silent fallback)
    fn infer_variable_type_inner(
        ssa: &SsaFunction,
        var: SsaVarId,
        visited: &mut BTreeSet<SsaVarId>,
    ) -> Result<SsaType> {
        if !visited.insert(var) {
            return Err(Error::CodegenFailed(format!(
                "circular type dependency for variable {var:?}"
            )));
        }

        // 1. Check variable's declared type
        if let Some(v) = ssa.variable(var) {
            if !v.var_type().is_unknown() {
                return Ok(v.var_type().clone());
            }
        }

        // 2. Try defining instruction (full SsaInstruction, not just SsaOp)
        if let Some(def_instr) = ssa.get_definition_instruction(var) {
            // 2a. Instruction-level result type (from converter — most precise,
            //     resolved via TypeContext with full metadata)
            if let Some(rt) = def_instr.result_type() {
                if !rt.is_unknown() {
                    return Ok(rt.clone());
                }
            }
            // 2b. Op structural inference (for ops with embedded type info like
            //     Const, Conv, LoadElement, LoadIndirect, etc.)
            if let Some(inferred) = def_instr.op().infer_result_type() {
                return Ok(inferred);
            }
            // 2c. Copy chain tracing
            if let SsaOp::Copy { src, .. } = def_instr.op() {
                let src = *src;
                return Self::infer_variable_type_inner(ssa, src, visited);
            }
            return Err(Error::CodegenFailed(format!(
                "cannot determine type for variable {var:?}: defining op has no \
                 type inference rule: {:?}",
                def_instr.op()
            )));
        }

        // 3. Check if defined by a phi — trace operands
        if let Some((_block, phi)) = ssa.find_phi_defining(var) {
            for operand in phi.operands() {
                if let Ok(ty) = Self::infer_variable_type_inner(ssa, operand.value(), visited) {
                    return Ok(ty);
                }
            }
            return Err(Error::CodegenFailed(format!(
                "cannot determine type for phi {var:?}: all operands unknown"
            )));
        }

        // 4. No definition found at all — error, not a silent fallback.
        Err(Error::CodegenFailed(format!(
            "cannot determine type for variable {var:?}: no definition found"
        )))
    }

    /// Gets the storage for an SSA variable.
    ///
    /// If the variable doesn't have directly allocated storage, this traces through
    /// the SSA definition chain to find a source variable that does. This is crucial
    /// for CFF reconstruction where phi copy variables might be defined in intermediate
    /// blocks that aren't part of the reconstructed SSA.
    ///
    /// # Errors
    ///
    /// Returns an error if no storage can be found for the variable. This indicates
    /// a bug in SSA construction - all variables referenced in instructions should
    /// have proper storage allocated or traceable through the SSA graph.
    fn get_storage(&self, var: SsaVarId, ssa: &SsaFunction) -> Result<VarStorage> {
        // Check if variable has direct storage allocation
        if let Some(&storage) = self.var_storage.get(&var) {
            return Ok(storage);
        }

        // Check if the variable has Argument or Local origin directly.
        // This handles cases where a variable wasn't pre-allocated in var_storage
        // but has an explicit origin that tells us where it should live.
        if let Some(ssa_var) = ssa.variable(var) {
            match ssa_var.origin() {
                VariableOrigin::Argument(idx) => return Ok(VarStorage::Arg(idx)),
                VariableOrigin::Local(idx) => {
                    // Use the compacted local slot if available
                    if let Some(&compacted) = self.original_to_compacted.get(&idx) {
                        return Ok(VarStorage::Local(compacted));
                    }
                    return Ok(VarStorage::Local(idx));
                }
                _ => {}
            }
        }

        // Variable not found - trace through SSA to find source with storage
        let traced = self.trace_to_storage(var, ssa, &mut BTreeSet::new());
        if let Some(storage) = traced {
            return Ok(storage);
        }

        // No storage found - this is a bug in SSA construction.
        // Gather diagnostic information to help identify the root cause.
        let var_info = if let Some(ssa_var) = ssa.variable(var) {
            format!(
                "origin={:?}, type={:?}, version={}",
                ssa_var.origin(),
                ssa_var.var_type(),
                ssa_var.version()
            )
        } else {
            "NOT IN SSA VARIABLE LIST (orphan)".to_string()
        };

        Err(Error::Deobfuscation(format!(
            "No storage found for variable {var:?} ({var_info}) - this indicates a bug in SSA construction. \
             Variables must have proper Argument/Local origins or be traceable through the SSA graph."
        )))
    }

    /// Traces through SSA definitions to find a variable with allocated storage.
    ///
    /// This handles cases where a Copy instruction references a variable defined
    /// in an intermediate block. We trace back through Copy chains and phi nodes
    /// to find the original variable that was allocated storage.
    ///
    /// For phi nodes, if all operands trace to the same storage, that storage is
    /// returned. This correctly handles cases where control flow obfuscation
    /// creates phi nodes for argument values.
    fn trace_to_storage(
        &self,
        var: SsaVarId,
        ssa: &SsaFunction,
        visited: &mut BTreeSet<SsaVarId>,
    ) -> Option<VarStorage> {
        // Prevent infinite loops
        if !visited.insert(var) {
            return None;
        }

        // Check if this variable has storage
        if let Some(&storage) = self.var_storage.get(&var) {
            return Some(storage);
        }

        // Look up the definition in instructions
        if let Some(def_op) = ssa.get_definition(var) {
            match def_op {
                // For Copy, trace to the source
                SsaOp::Copy { src, .. } => {
                    return self.trace_to_storage(*src, ssa, visited);
                }
                // For other ops, try operands
                _ => {
                    for operand in def_op.uses() {
                        if let Some(storage) = self.trace_to_storage(operand, ssa, visited) {
                            return Some(storage);
                        }
                    }
                }
            }
        }

        // Check if defined by a phi node
        // If all phi operands trace to the same storage, return that storage
        if let Some((_, phi)) = ssa.find_phi_defining(var) {
            let operands = phi.operands();
            if let Some(first_op) = operands.first() {
                // Trace the first operand to get a reference storage
                let first_storage = self.trace_to_storage(first_op.value(), ssa, visited)?;

                // Check if all other operands trace to the same storage
                for operand in operands.iter().skip(1) {
                    // Skip self-references (phi referring to itself in loops)
                    if operand.value() == var {
                        continue;
                    }
                    let op_storage = self.trace_to_storage(operand.value(), ssa, visited)?;
                    if op_storage != first_storage {
                        // Different storage for different operands - can't determine unique storage
                        return None;
                    }
                }

                return Some(first_storage);
            }
        }

        None
    }

    /// Checks if a variable is immediately consumed by the next operation.
    ///
    /// This is used to determine if we can leave a value on the stack instead
    /// of storing it to a local. A value can stay on the stack if:
    ///
    /// 1. The next instruction uses it as an operand
    /// 2. It's either the first operand, OR all prior operands can be loaded
    ///    without disturbing the stack (i.e., they're simple loads like ldarg/ldloc)
    ///
    /// For binary operations where the value is the second operand (like shift amount),
    /// we check if the first operand is a "simple" load that won't need the stack.
    fn is_immediately_consumed(&self, var: SsaVarId, next_op: Option<&SsaOp>) -> bool {
        let Some(next) = next_op else {
            return false;
        };

        match next {
            // Return immediately consumes its value
            SsaOp::Return { value: Some(v) } if *v == var => true,

            // Branch immediately consumes its condition
            SsaOp::Branch { condition, .. } if *condition == var => true,

            // BranchCmp consumes left operand first, then right
            SsaOp::BranchCmp { left, .. } if *left == var => true,

            // These ops consume their first operand (left) immediately
            SsaOp::Add { left, .. }
            | SsaOp::Sub { left, .. }
            | SsaOp::Mul { left, .. }
            | SsaOp::Div { left, .. }
            | SsaOp::Rem { left, .. }
            | SsaOp::And { left, .. }
            | SsaOp::Or { left, .. }
            | SsaOp::Xor { left, .. }
            | SsaOp::Ceq { left, .. }
            | SsaOp::Clt { left, .. }
            | SsaOp::Cgt { left, .. }
                if *left == var =>
            {
                true
            }

            // Binary ops can also consume their second operand (right) if first is simple
            SsaOp::Add { left, right, .. }
            | SsaOp::Sub { left, right, .. }
            | SsaOp::Mul { left, right, .. }
            | SsaOp::Div { left, right, .. }
            | SsaOp::Rem { left, right, .. }
            | SsaOp::And { left, right, .. }
            | SsaOp::Or { left, right, .. }
            | SsaOp::Xor { left, right, .. }
            | SsaOp::Ceq { left, right, .. }
            | SsaOp::Clt { left, right, .. }
            | SsaOp::Cgt { left, right, .. }
            | SsaOp::BranchCmp { left, right, .. }
                if *right == var && self.is_simple_load(*left) =>
            {
                true
            }

            // Shift ops consume their first operand (value) immediately
            SsaOp::Shl { value, .. } | SsaOp::Shr { value, .. } if *value == var => true,

            // Shift ops can consume amount if value is a simple load
            SsaOp::Shl { value, amount, .. } | SsaOp::Shr { value, amount, .. }
                if *amount == var && self.is_simple_load(*value) =>
            {
                true
            }

            // Unary ops consume their operand
            SsaOp::Neg { operand, .. }
            | SsaOp::Not { operand, .. }
            | SsaOp::Conv { operand, .. }
            | SsaOp::Ckfinite { operand, .. }
                if *operand == var =>
            {
                true
            }

            // Throw consumes its exception
            SsaOp::Throw { exception } if *exception == var => true,

            // Pop consumes its value
            SsaOp::Pop { value } if *value == var => true,

            _ => false,
        }
    }

    /// Checks if a variable can be loaded with a simple instruction that doesn't
    /// disturb the evaluation stack. This is true for arguments and locals.
    fn is_simple_load(&self, var: SsaVarId) -> bool {
        matches!(
            self.var_storage.get(&var),
            Some(VarStorage::Arg(_) | VarStorage::Local(_))
        )
    }

    /// Generates code for a single basic block with instruction scheduling.
    ///
    /// This method schedules instructions to minimize local variable usage by
    /// reordering value definitions to occur immediately before their use.
    /// This is particularly important for stack-based code generation where
    /// we want to leave values on the stack rather than storing to locals.
    fn generate_block(
        &mut self,
        encoder: &mut InstructionEncoder,
        ssa: &SsaFunction,
        block: &SsaBlock,
        block_idx: usize,
        next_block_idx: Option<usize>,
    ) -> Result<()> {
        // Exception handler entry blocks (catch, filter, finally, fault) are only
        // entered via CLR exception dispatch — never via fallthrough from the previous
        // block in the layout. Mark the encoder as unreachable before defining the label
        // so that define_label resets the stack depth to the expected handler entry depth
        // (e.g., 1 for catch/filter) rather than conflicting with the previous block's
        // fallthrough depth.
        let is_handler_entry = ssa.exception_handlers().iter().any(|h| {
            h.handler_start_block == Some(block_idx) || h.filter_start_block == Some(block_idx)
        });
        if is_handler_entry {
            encoder.mark_unreachable();
        }

        // Define the block label - the encoder validates stack depth consistency
        // across all control flow paths reaching this label.
        let label = self
            .block_labels
            .get(&block_idx)
            .ok_or_else(|| Error::SsaError(format!("Missing label for block {block_idx}")))?
            .clone();
        encoder.define_label(&label)?;

        // Reset tracked stack variables at block boundary
        self.stack_vars.clear();

        // Collect actual ops (non-None) for scheduling, filtering out:
        // - No-op Copy operations (src and dest share same storage due to coalescing)
        // - Nop operations (produce unnecessary bytecode)
        // - Deferred Const operations (will be generated inline at use site)
        let ops: Vec<&SsaOp> = block
            .instructions()
            .iter()
            .map(SsaInstruction::op)
            .filter(|op| {
                match op {
                    SsaOp::Copy { dest, src } => {
                        // Skip Copy if src and dest are coalesced to same storage
                        let src_storage = self.var_storage.get(src);
                        let dest_storage = self.var_storage.get(dest);
                        src_storage != dest_storage || src_storage.is_none()
                    }
                    SsaOp::Const { dest, .. } => {
                        // Skip deferred constants - generated inline at use site.
                        // Also skip dead constants (0 uses, not a phi operand) —
                        // these are CFF state computation artifacts that DCE missed.
                        // Emitting them would push values onto the CIL stack with
                        // no consumer, causing stack depth mismatches at merge points.
                        if self.deferred_constants.contains_key(dest) {
                            return false;
                        }
                        let uses = self.global_use_counts.get(dest).copied().unwrap_or(0);
                        if uses == 0 && !self.all_phi_operands.contains(dest) {
                            // Keep stores to address-taken locals: the value is
                            // read through a pointer (LoadLocalAddr), not via SSA
                            // uses, so 0 SSA uses doesn't mean the store is dead.
                            if let Some(var) = ssa.variable(*dest) {
                                if let VariableOrigin::Local(idx) = var.origin() {
                                    if self.address_taken_locals.contains(&idx) {
                                        return true;
                                    }
                                }
                            }
                            return false;
                        }
                        true
                    }
                    SsaOp::Nop => false, // Skip Nop - produces unnecessary bytecode
                    _ => true,
                }
            })
            .collect();
        if ops.is_empty() {
            // Block has no decomposed ops - it's an empty block (e.g., a merge point created
            // by control flow unflattening or other SSA transformations).
            //
            // If the original block also has no terminator, there is no meaningful fallthrough —
            // mark as unreachable so the stack depth doesn't leak to the next block in the layout.
            // This is critical for empty exception handler entry blocks whose pre-set depth (1 for
            // catch/filter) would otherwise propagate incorrectly to unrelated successor blocks.
            if block.terminator_op().is_none() {
                encoder.mark_unreachable();
            }
            return Ok(());
        }

        // Pre-compute operands for each instruction (avoid repeated calls)
        let mut operands_cache: Vec<Vec<SsaVarId>> = ops
            .iter()
            .map(|op| Self::get_operands_in_stack_order(op))
            .collect();

        // For exception/filter handler entry blocks, the exception object is already
        // on the stack when execution enters the handler. Pop instructions that pop
        // this exception object should NOT try to load it first - it's already there.
        //
        // We identify handler entry blocks by checking if this block is a handler_start_block
        // for an EXCEPTION or FILTER handler.
        let is_exception_handler_entry = ssa.exception_handlers().iter().any(|h| {
            h.handler_start_block == Some(block_idx)
                && (h.flags == ExceptionHandlerFlags::EXCEPTION
                    || h.flags == ExceptionHandlerFlags::FILTER)
        });
        let is_filter_entry = ssa.exception_handlers().iter().any(|h| {
            h.filter_start_block == Some(block_idx) && h.flags == ExceptionHandlerFlags::FILTER
        });

        if is_exception_handler_entry || is_filter_entry {
            // Clear operands for Pop instructions that consume the exception object.
            // The exception object is already on the stack when entering the handler.
            // We only clear operands for Pop instructions where the value being popped
            // is NOT defined in this block (meaning it's the exception object from outside).
            //
            // First, collect all variables defined in this block
            let mut defined_in_block: BTreeSet<SsaVarId> = BTreeSet::new();
            for op in &ops {
                if let Some(dest) = op.dest() {
                    defined_in_block.insert(dest);
                }
            }

            // Clear operands for Pop instructions that consume the exception object,
            // and track whether any such Pop exists.
            let mut has_exception_pop = false;
            for (idx, op) in ops.iter().enumerate() {
                if let SsaOp::Pop { value } = op {
                    if !defined_in_block.contains(value) {
                        // This Pop consumes a value not defined in this block
                        // (the exception object), so clear its operands
                        if let Some(ops_at_idx) = operands_cache.get_mut(idx) {
                            ops_at_idx.clear();
                        }
                        has_exception_pop = true;
                    }
                }
            }

            // If no Pop instruction consumes the exception object, it remains on
            // the CIL evaluation stack. This happens when dead code elimination
            // removes an unused exception object store. Emit an explicit pop to
            // discard the exception object and maintain stack balance.
            if !has_exception_pop {
                encoder.emit_instruction("pop", None)?;
            }
        }

        // Build def map: variable -> instruction index
        let mut def_map: BTreeMap<SsaVarId, usize> = BTreeMap::new();
        for (idx, op) in ops.iter().enumerate() {
            if let Some(dest) = op.dest() {
                def_map.insert(dest, idx);
            }
        }

        // Identify which variables are used as operands in this block
        let mut used_in_block: BTreeSet<SsaVarId> = BTreeSet::new();
        for operands in &operands_cache {
            for var in operands {
                used_in_block.insert(*var);
            }
        }

        // Find root ops - those whose results are NOT used by other ops
        // in this block (they're terminators, have side effects, or export to other blocks)
        let roots: Vec<usize> = ops
            .iter()
            .enumerate()
            .filter_map(|(idx, op)| {
                let is_root = match op.dest() {
                    Some(dest) => !used_in_block.contains(&dest) || Self::is_terminator(op),
                    None => true, // No dest = side effect only, always a root
                };
                if is_root {
                    Some(idx)
                } else {
                    None
                }
            })
            .collect();

        // Generate code iteratively using explicit work stack
        let ctx = BlockCodegenContext {
            ssa,
            ops: &ops,
            operands_cache: &operands_cache,
            def_map: &def_map,
            current_block_idx: block_idx,
        };
        self.generate_ops_iterative(encoder, &ctx, &roots, next_block_idx)?;

        // Check if the block ends with a non-terminator (falls through to next block)
        // If so, spill remaining stack values and emit phi stores for the fallthrough
        let has_terminator = ops.last().is_some_and(|op| Self::is_terminator(op));
        if !has_terminator {
            // Spill any remaining stack values before fallthrough
            self.spill_stack(encoder, ssa)?;

            if let Some(next_idx) = next_block_idx {
                self.emit_phi_stores_for_successor(encoder, ssa, block_idx, next_idx)?;
            }
        }

        Ok(())
    }

    /// Generates ops iteratively with dependency tracking.
    ///
    /// Uses an explicit work stack instead of recursion to avoid stack overflow
    /// on deep dependency chains and improve cache locality.
    ///
    /// The key insight is that operands must be loaded/generated in order.
    /// We use three phases:
    /// - `Pending`: Schedule operand loads in reverse order, then Emit
    /// - `LoadOperand`: Load or generate a specific operand
    /// - `Emit`: All operands on stack, emit the operation
    fn generate_ops_iterative(
        &mut self,
        encoder: &mut InstructionEncoder,
        ctx: &BlockCodegenContext<'_>,
        roots: &[usize],
        next_block_idx: Option<usize>,
    ) -> Result<()> {
        // Use global use counts to determine if variables need storage.
        // Variables used multiple times (across ANY blocks) must be stored to locals
        // so subsequent uses can load from them. This is critical for cross-block
        // data flow where a value is defined in one block and used in another.
        //
        // Note: We use the global use_counts computed during allocate_storage().
        // Phi operand uses are NOT included in global_use_counts, so phi operand
        // values that are only used as phi operands will have use_count=0 and
        // remain on the stack until the phi stores consume them.
        //
        // If a phi operand value gets "buried" (other operations push values on
        // top of it), the buried handling in load_var will store it to a local
        // and the phi stores will load it from there.
        //
        // Clone is required here: `generate_op_core` (called via the work loop)
        // may invoke branch handlers that read `self.global_use_counts` through
        // `successor_has_phi_from` / `emit_phi_stores_for_successor`. Since those
        // access `self` directly, we cannot borrow `self.global_use_counts` while
        // also passing `&mut self` to those methods.
        let use_counts = self.global_use_counts.clone();

        let mut generated: BTreeSet<usize> = BTreeSet::new();
        // Track which Pending items are already scheduled to avoid re-pushing
        let mut scheduled_pending: BTreeSet<usize> = BTreeSet::new();
        // Track which operations are "in progress" (between Pending and Emit).
        // Used for cycle detection - if we need a dependency that's in_progress,
        // we have a cyclic dependency which indicates invalid SSA.
        let mut in_progress: BTreeSet<usize> = BTreeSet::new();
        // Track which LoadOperand (idx, operand_idx) pairs are already scheduled
        let mut scheduled_load: BTreeSet<(usize, usize)> = BTreeSet::new();
        let mut work_stack: Vec<CodeGenWorkItem> =
            Vec::with_capacity(ctx.ops.len().saturating_mul(3));

        // Preserve original instruction order as much as possible.
        // For malware analysis and understanding original intent, the order matters.
        //
        // However, Copy roots require special handling with parallel copy semantics.
        // They may form dependency/storage conflicts like:
        //   v47 = add(v45, v46)  // reads Local(0), Local(1)
        //   v49 = v46            // writes Local(0), reads Local(1)
        //   v50 = v48            // writes Local(1), depends on v47
        //
        // Neither processing order works:
        //   - v49 first: clobbers Local(0) before v47 reads it
        //   - v50 first: v50 stores to Local(1) before v49 reads it
        //
        // Solution: Handle Copy roots with parallel copy semantics AFTER all
        // non-Copy roots are processed. We'll generate their dependencies, load
        // all sources, then store all destinations.
        let mut terminator_roots: Vec<usize> = Vec::new();
        let mut copy_roots: Vec<usize> = Vec::new();
        let mut other_roots: Vec<usize> = Vec::new();
        for &root_idx in roots {
            let op = ctx
                .ops
                .get(root_idx)
                .ok_or_else(|| Error::CodegenFailed("root index out of bounds".to_string()))?;
            if Self::is_terminator(op) {
                terminator_roots.push(root_idx);
            } else if matches!(op, SsaOp::Copy { .. }) {
                copy_roots.push(root_idx);
            } else {
                other_roots.push(root_idx);
            }
        }

        // Push non-Copy roots in reverse priority order (stack is LIFO):
        // - If there are Copy roots, DON'T push terminators here - they need to come
        //   AFTER the Copy roots and their dependencies are emitted.
        // - Other roots (non-Copy, non-terminator) are processed first.
        // Note: Copy roots are NOT pushed here - they're handled specially below.
        let defer_terminators = !copy_roots.is_empty();
        if !defer_terminators {
            for root_idx in terminator_roots.iter().rev() {
                work_stack.push(CodeGenWorkItem::Pending(*root_idx));
                scheduled_pending.insert(*root_idx);
            }
        }
        for root_idx in other_roots.into_iter().rev() {
            work_stack.push(CodeGenWorkItem::Pending(root_idx));
            scheduled_pending.insert(root_idx);
        }

        while let Some(item) = work_stack.pop() {
            match item {
                CodeGenWorkItem::Pending(idx) => {
                    scheduled_pending.remove(&idx);
                    if generated.contains(&idx) {
                        continue; // Already done
                    }

                    // Mark as in_progress for cycle detection
                    in_progress.insert(idx);

                    // Spill stack_vars that would be buried by operand loads.
                    //
                    // When loading operands for an operation, some come from the
                    // CIL stack (tracked in stack_vars) and some from storage
                    // (ldloc/ldarg). Loading from storage pushes onto the CIL stack,
                    // which can bury values in stack_vars.
                    //
                    // Optimization: if the first operand (loaded first, bottom of
                    // CIL stack) matches the stack_vars top, it can stay on the
                    // stack — the LoadOperand handler will consume it directly.
                    // Subsequent operands that need storage loads will be pushed on
                    // top of it, which is the correct CIL evaluation order.
                    //
                    // Only spill when the first operand does NOT match the stack
                    // top, because loading it from storage would bury the tracked
                    // stack values.
                    let operands = ctx.operands_cache.get(idx).ok_or_else(|| {
                        Error::CodegenFailed("operands_cache index out of bounds".to_string())
                    })?;
                    let first_operand_on_stack = operands.first().is_some_and(|first_op| {
                        self.stack_vars.last().is_some_and(|top| *top == *first_op)
                    });

                    if !first_operand_on_stack && !self.stack_vars.is_empty() {
                        let needs_storage_load = operands
                            .iter()
                            .any(|op_var| self.stack_vars.last().is_none_or(|top| *top != *op_var));
                        if needs_storage_load {
                            self.spill_stack(encoder, ctx.ssa)?;
                        }
                    }

                    // Schedule: first Emit (pushed first, runs last),
                    // then LoadOperand for each operand in reverse order
                    work_stack.push(CodeGenWorkItem::Emit(idx));

                    for (op_idx, _) in operands.iter().enumerate().rev() {
                        if !scheduled_load.contains(&(idx, op_idx)) {
                            work_stack.push(CodeGenWorkItem::LoadOperand(idx, op_idx));
                            scheduled_load.insert((idx, op_idx));
                        }
                    }
                }

                CodeGenWorkItem::LoadOperand(idx, operand_idx) => {
                    scheduled_load.remove(&(idx, operand_idx));
                    let operand = *ctx
                        .operands_cache
                        .get(idx)
                        .and_then(|ops| ops.get(operand_idx))
                        .ok_or_else(|| {
                            Error::CodegenFailed("operands_cache index out of bounds".to_string())
                        })?;

                    if let Some(&dep_idx) = ctx.def_map.get(&operand) {
                        // Operand is defined in this block
                        if generated.contains(&dep_idx) {
                            // Already generated - load from storage or stack
                            self.load_var(encoder, ctx.ssa, operand)?;
                        } else if let Some(SsaOp::Copy { src, .. }) = ctx.ops.get(dep_idx) {
                            // Operand is defined by a Copy that hasn't been generated yet.
                            // This can happen with circular dependencies through Copy chains
                            // (e.g., Add needs Copy result, Copy needs Add result).
                            // Load the Copy's SOURCE instead - it should be available from
                            // storage (from a previous block/iteration) or will be generated
                            // and stored by the copy_roots handling.
                            self.load_var(encoder, ctx.ssa, *src)?;
                        } else {
                            // Not yet generated - check for cyclic dependency.
                            // If this dependency is "in progress" (between Pending and Emit),
                            // we have a cycle - operation A needs B, but B needs A.
                            if in_progress.contains(&dep_idx) {
                                // This is a cyclic dependency between non-Copy operations,
                                // which indicates invalid SSA. All operations within a block
                                // should have a valid topological order.
                                let cur_op = ctx.ops.get(idx);
                                let dep_op = ctx.ops.get(dep_idx);
                                return Err(Error::Deobfuscation(format!(
                                    "Cyclic dependency detected in block {}: \
                                     op {:?} needs {:?} (defined by {:?}), \
                                     but that definition is already being processed. \
                                     This indicates invalid SSA form.",
                                    ctx.current_block_idx, cur_op, operand, dep_op
                                )));
                            }

                            // Generate it now.
                            // Schedule a load AFTER the generation completes.
                            // This is needed because the value might be stored (if buried by
                            // other operand loads) and not left on the stack.
                            if !scheduled_load.contains(&(idx, operand_idx)) {
                                work_stack.push(CodeGenWorkItem::LoadOperand(idx, operand_idx));
                                scheduled_load.insert((idx, operand_idx));
                            }
                            // Generate the dependency
                            if !generated.contains(&dep_idx) {
                                work_stack.push(CodeGenWorkItem::Pending(dep_idx));
                                scheduled_pending.insert(dep_idx);
                            }
                        }
                    } else {
                        // External variable - load from arg/local
                        self.load_var(encoder, ctx.ssa, operand)?;
                    }
                }

                CodeGenWorkItem::Emit(idx) => {
                    // Remove from in_progress (no longer being processed)
                    in_progress.remove(&idx);

                    if generated.contains(&idx) {
                        continue; // Already done
                    }

                    let cur_op = *ctx.ops.get(idx).ok_or_else(|| {
                        Error::CodegenFailed("ops index out of bounds".to_string())
                    })?;

                    // Generate the operation (operands should be on stack)
                    self.generate_op_core(
                        encoder,
                        ctx.ssa,
                        ctx.current_block_idx,
                        cur_op,
                        next_block_idx,
                    )?;
                    generated.insert(idx);

                    // If this op produces a value, handle it based on use count
                    // and whether it's used outside this block (cross-block use).
                    // Note: Skip Copy instructions - they handle their own storage
                    // in generate_op_core and don't leave a result on the stack.
                    let is_copy = matches!(cur_op, SsaOp::Copy { .. });
                    if !is_copy {
                        if let Some(dest) = cur_op.dest() {
                            let uses = use_counts.get(&dest).copied().unwrap_or(0);
                            // Check if this value is used outside the current block.
                            // If so, it must be stored because stack values don't
                            // persist across block boundaries.
                            let used_outside_block = self.cross_block_uses.contains(&dest);

                            if uses > 1 || used_outside_block {
                                // Multi-use or cross-block use: must store to a local.
                                //
                                // Optimization: if the next pending work item will load
                                // this same variable, emit `dup; stloc.N` instead of
                                // `stloc.N` followed by a later `ldloc.N`. The `dup`
                                // keeps a copy on the evaluation stack for the immediate
                                // consumer while `stloc` persists it for later uses.
                                // This avoids a redundant store-then-load round-trip.
                                let next_loads_dest =
                                    work_stack.last().is_some_and(|item| match item {
                                        CodeGenWorkItem::LoadOperand(consumer_idx, op_idx) => ctx
                                            .operands_cache
                                            .get(*consumer_idx)
                                            .and_then(|ops| ops.get(*op_idx))
                                            .is_some_and(|op| *op == dest),
                                        _ => false,
                                    });

                                if next_loads_dest {
                                    // Emit dup (keeps value on stack) then store.
                                    encoder.emit_instruction("dup", None)?;
                                    self.store_var(encoder, ctx.ssa, dest)?;
                                    // Pop the LoadOperand — the value is already on the
                                    // stack from dup, so the load is satisfied.
                                    work_stack.pop();
                                } else {
                                    self.store_var(encoder, ctx.ssa, dest)?;
                                }
                            } else {
                                // Single-use value within this block: leave on stack for now.
                                // The consumer should use it directly. Storage will be allocated
                                // lazily if this value gets buried and needs to be saved.
                                self.stack_vars.push(dest);
                            }
                        }
                    }
                }
            }
        }

        // Handle Copy roots with parallel copy semantics.
        // This ensures all sources are loaded before any destinations are stored,
        // preventing read-after-write hazards.
        if !copy_roots.is_empty() {
            self.emit_copy_roots_parallel(encoder, ctx, &copy_roots, &mut generated, &use_counts)?;

            // Now process terminators that were deferred.
            // Terminators must come after Copy roots because:
            // 1. Copy roots may have dependencies (like Add) that need to be generated
            // 2. Those dependencies must execute before the terminator
            // 3. The terminator (e.g., Jump) may emit phi stores that depend on the Copy results
            for &root_idx in &terminator_roots {
                if !generated.contains(&root_idx) {
                    let root_operands = ctx.operands_cache.get(root_idx).ok_or_else(|| {
                        Error::CodegenFailed("operands_cache index out of bounds".to_string())
                    })?;
                    let root_op = *ctx.ops.get(root_idx).ok_or_else(|| {
                        Error::CodegenFailed("ops index out of bounds".to_string())
                    })?;
                    // Load any operands the terminator needs.
                    // Always use load_var which handles buried values correctly.
                    for &operand in root_operands {
                        self.load_var(encoder, ctx.ssa, operand)?;
                    }
                    self.generate_op_core(
                        encoder,
                        ctx.ssa,
                        ctx.current_block_idx,
                        root_op,
                        next_block_idx,
                    )?;
                    generated.insert(root_idx);
                }
            }
        }

        Ok(())
    }

    /// Emits Copy root operations with parallel copy semantics.
    ///
    /// Copy roots may have dependencies (other ops that produce their sources)
    /// and may conflict with each other (one reads a local another writes).
    /// This function handles these conflicts by:
    /// 1. Generating all dependencies of all Copy roots
    /// 2. Loading all source values (using temps for conflicts)
    /// 3. Storing all destinations
    fn emit_copy_roots_parallel(
        &mut self,
        encoder: &mut InstructionEncoder,
        ctx: &BlockCodegenContext<'_>,
        copy_roots: &[usize],
        generated: &mut BTreeSet<usize>,
        use_counts: &BTreeMap<SsaVarId, usize>,
    ) -> Result<()> {
        struct CopyInfo {
            src_var: SsaVarId,
            dest_var: SsaVarId,
            dest_storage: VarStorage,
        }

        // Phase 1: Generate all dependencies of all Copy roots.
        // This ensures operations like Add are completed before any Copy stores.
        let mut visiting = BTreeSet::new();
        for &copy_idx in copy_roots {
            self.generate_copy_deps_recursive(
                encoder,
                ctx,
                copy_idx,
                generated,
                &mut visiting,
                use_counts,
            )?;
        }

        // Phase 2: Collect all copy operations and their storage info.
        // For each Copy root, we need its source value and destination storage.
        let mut copies: Vec<CopyInfo> = Vec::new();

        for &copy_idx in copy_roots {
            if generated.contains(&copy_idx) {
                continue;
            }
            let Some(&op) = ctx.ops.get(copy_idx) else {
                continue;
            };
            if let SsaOp::Copy { dest, src } = op {
                let dest_storage = self.get_or_allocate_storage(ctx.ssa, *dest)?;
                copies.push(CopyInfo {
                    src_var: *src,
                    dest_var: *dest,
                    dest_storage,
                });
            }
        }

        if copies.is_empty() {
            return Ok(());
        }

        // Phase 3: Detect interference - does any copy read from a local that
        // another copy writes to?
        let has_interference = copies.iter().any(|copy_a| {
            // Get the storage of copy_a's source
            let src_storage = self
                .var_storage
                .get(&copy_a.src_var)
                .copied()
                .unwrap_or(VarStorage::Stack);

            // Check if any other copy writes to this storage
            copies
                .iter()
                .any(|copy_b| !std::ptr::eq(copy_a, copy_b) && src_storage == copy_b.dest_storage)
        });

        if has_interference {
            // Interference detected: use parallel copy semantics.
            // Load all sources first, storing to temporaries.
            // Use the temp pool for slot reuse.
            let mut temps: Vec<(u16, SsaType, VarStorage, SsaVarId)> = Vec::new();
            for copy_info in &copies {
                self.load_var(encoder, ctx.ssa, copy_info.src_var)?;

                // Determine the type for this temporary
                let var_type = Self::infer_variable_type(ctx.ssa, copy_info.src_var)?;

                // Allocate from pool or fresh
                let temp_idx = self.allocate_temp_local(&var_type);

                self.used_locals.insert(temp_idx);
                emitter::emit_stloc(encoder, temp_idx)?;
                self.last_load = None;
                temps.push((
                    temp_idx,
                    var_type,
                    copy_info.dest_storage,
                    copy_info.dest_var,
                ));
            }

            // Now store from temporaries to destinations, then release temps
            for (temp_idx, var_type, dest_storage, dest_var) in temps {
                self.used_locals.insert(temp_idx);
                emitter::emit_ldloc(encoder, temp_idx)?;
                match dest_storage {
                    VarStorage::Local(idx) => {
                        self.used_locals.insert(idx);
                        emitter::emit_stloc(encoder, idx)?;
                    }
                    VarStorage::Arg(idx) => emitter::emit_starg(encoder, idx)?,
                    VarStorage::Stack => {
                        return Err(Error::Deobfuscation(format!(
                            "emit_copy_roots_parallel: copy destination {dest_var:?} has Stack storage - this indicates a bug in storage allocation"
                        )));
                    }
                }
                self.last_load = None;

                // Release temp back to pool for reuse
                self.release_temp_local(temp_idx, &var_type);
            }
        } else {
            // Simple case: no interference, emit load-store pairs directly
            for copy_info in &copies {
                self.load_var(encoder, ctx.ssa, copy_info.src_var)?;
                match copy_info.dest_storage {
                    VarStorage::Local(idx) => {
                        self.used_locals.insert(idx);
                        emitter::emit_stloc(encoder, idx)?;
                    }
                    VarStorage::Arg(idx) => emitter::emit_starg(encoder, idx)?,
                    VarStorage::Stack => {
                        return Err(Error::Deobfuscation(format!(
                            "emit_copy_roots_parallel: copy destination {:?} has Stack storage - this indicates a bug in storage allocation",
                            copy_info.dest_var
                        )));
                    }
                }
                self.last_load = None;
            }
        }

        // Mark all Copy roots as generated
        for &copy_idx in copy_roots {
            generated.insert(copy_idx);
        }

        Ok(())
    }

    /// Recursively generates dependencies of a Copy root.
    ///
    /// Uses a `visiting` set for cycle detection: if a dependency is already
    /// being visited (but not yet fully generated), we have a circular
    /// dependency chain and break it by skipping the recursion. The variable
    /// will be loaded from its existing storage location instead.
    fn generate_copy_deps_recursive(
        &mut self,
        encoder: &mut InstructionEncoder,
        ctx: &BlockCodegenContext<'_>,
        idx: usize,
        generated: &mut BTreeSet<usize>,
        visiting: &mut BTreeSet<usize>,
        use_counts: &BTreeMap<SsaVarId, usize>,
    ) -> Result<()> {
        if !visiting.insert(idx) {
            return Ok(());
        }

        let operands = ctx.operands_cache.get(idx).ok_or_else(|| {
            Error::CodegenFailed("operands_cache index out of bounds".to_string())
        })?;

        for &operand in operands {
            if let Some(&dep_idx) = ctx.def_map.get(&operand) {
                if !generated.contains(&dep_idx) {
                    self.generate_copy_deps_recursive(
                        encoder, ctx, dep_idx, generated, visiting, use_counts,
                    )?;

                    let dep_op = *ctx.ops.get(dep_idx).ok_or_else(|| {
                        Error::CodegenFailed("ops index out of bounds".to_string())
                    })?;

                    // Skip Copy ops - they'll be handled in the parallel copy phase
                    if matches!(dep_op, SsaOp::Copy { .. }) {
                        continue;
                    }

                    // Spill all stack_vars BEFORE loading operands to avoid the issue where
                    // loading some operands from storage buries stack_vars values, causing
                    // subsequent spills to store the wrong values.
                    if !self.stack_vars.is_empty() {
                        self.spill_stack(encoder, ctx.ssa)?;
                    }

                    let dep_operands = ctx.operands_cache.get(dep_idx).ok_or_else(|| {
                        Error::CodegenFailed("operands_cache index out of bounds".to_string())
                    })?;

                    // Generate operands for this dependency
                    for &dep_operand in dep_operands {
                        if let Some(&dep_dep_idx) = ctx.def_map.get(&dep_operand) {
                            let dep_dep_op = ctx.ops.get(dep_dep_idx).copied();
                            if generated.contains(&dep_dep_idx) {
                                // Operand's defining op is generated, load it
                                self.load_var(encoder, ctx.ssa, dep_operand)?;
                            } else if matches!(dep_dep_op, Some(SsaOp::Copy { .. })) {
                                // Operand is a Copy result that hasn't been generated.
                                // Load the Copy's source instead - it should be available.
                                let Some(SsaOp::Copy { src, .. }) = dep_dep_op else {
                                    return Err(Error::CodegenFailed(
                                        "Copy op pattern mismatch".to_string(),
                                    ));
                                };
                                self.load_var(encoder, ctx.ssa, *src)?;
                            } else {
                                // The operand's defining op should have been generated
                                // by the recursive call above. If we get here, something
                                // unexpected happened - load it anyway to avoid stack underflow.
                                self.load_var(encoder, ctx.ssa, dep_operand)?;
                            }
                        } else {
                            // External operand
                            self.load_var(encoder, ctx.ssa, dep_operand)?;
                        }
                    }

                    self.generate_op_core(encoder, ctx.ssa, ctx.current_block_idx, dep_op, None)?;
                    generated.insert(dep_idx);

                    // Handle storage for the result
                    if let Some(dest) = dep_op.dest() {
                        let uses = use_counts.get(&dest).copied().unwrap_or(0);
                        let used_outside_block = self.cross_block_uses.contains(&dest);

                        if uses > 1 || used_outside_block {
                            self.store_var(encoder, ctx.ssa, dest)?;
                        } else {
                            self.stack_vars.push(dest);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Generates just the core operation, assuming operands are already on the stack.
    fn generate_op_core(
        &mut self,
        encoder: &mut InstructionEncoder,
        ssa: &SsaFunction,
        current_block_idx: usize,
        op: &SsaOp,
        next_block_idx: Option<usize>,
    ) -> Result<()> {
        // Clear last_load tracking - after any operation, the stack state changes
        // and the "last loaded" value may no longer be on top of the stack.
        self.last_load = None;

        match op {
            SsaOp::Const { dest, value } => {
                self.generate_const(encoder, value)?;
                // Don't store - the caller will handle the value
                // (it's left on the stack for the consumer)
                let _ = dest; // Silence unused warning
            }

            // Arithmetic and bitwise operations
            SsaOp::Add { .. }
            | SsaOp::Sub { .. }
            | SsaOp::Mul { .. }
            | SsaOp::Div { .. }
            | SsaOp::Rem { .. }
            | SsaOp::AddOvf { .. }
            | SsaOp::SubOvf { .. }
            | SsaOp::MulOvf { .. }
            | SsaOp::And { .. }
            | SsaOp::Or { .. }
            | SsaOp::Xor { .. }
            | SsaOp::Shl { .. }
            | SsaOp::Shr { .. }
            | SsaOp::Neg { .. }
            | SsaOp::Not { .. } => Self::generate_arithmetic_op(encoder, op)?,

            // Conversion operations
            SsaOp::Conv { .. } | SsaOp::Ckfinite { .. } => {
                Self::generate_conversion_op(encoder, op)?;
            }

            // Comparison operations
            SsaOp::Ceq { .. } | SsaOp::Clt { .. } | SsaOp::Cgt { .. } => {
                Self::generate_comparison_op(encoder, op)?;
            }

            // Call operations
            SsaOp::Call { .. }
            | SsaOp::CallVirt { .. }
            | SsaOp::CallIndirect { .. }
            | SsaOp::NewObj { .. } => Self::generate_call_op(encoder, op)?,

            // Load, store, and memory operations
            SsaOp::Copy { .. }
            | SsaOp::LoadField { .. }
            | SsaOp::StoreField { .. }
            | SsaOp::LoadStaticField { .. }
            | SsaOp::StoreStaticField { .. }
            | SsaOp::LoadElement { .. }
            | SsaOp::StoreElement { .. }
            | SsaOp::ArrayLength { .. }
            | SsaOp::NewArr { .. }
            | SsaOp::Box { .. }
            | SsaOp::Unbox { .. }
            | SsaOp::UnboxAny { .. }
            | SsaOp::CastClass { .. }
            | SsaOp::IsInst { .. }
            | SsaOp::SizeOf { .. }
            | SsaOp::LoadToken { .. }
            | SsaOp::LoadArg { .. }
            | SsaOp::LoadLocal { .. }
            | SsaOp::LoadArgAddr { .. }
            | SsaOp::LoadLocalAddr { .. }
            | SsaOp::LoadFieldAddr { .. }
            | SsaOp::LoadStaticFieldAddr { .. }
            | SsaOp::LoadFunctionPtr { .. }
            | SsaOp::LoadVirtFunctionPtr { .. }
            | SsaOp::LocalAlloc { .. }
            | SsaOp::InitObj { .. }
            | SsaOp::LoadObj { .. }
            | SsaOp::StoreObj { .. }
            | SsaOp::LoadIndirect { .. }
            | SsaOp::StoreIndirect { .. }
            | SsaOp::LoadElementAddr { .. }
            | SsaOp::InitBlk { .. }
            | SsaOp::CopyBlk { .. }
            | SsaOp::CopyObj { .. } => self.generate_load_store_op(encoder, ssa, op)?,

            // Branch and control flow operations
            SsaOp::Return { .. }
            | SsaOp::Jump { .. }
            | SsaOp::Branch { .. }
            | SsaOp::Switch { .. }
            | SsaOp::Throw { .. }
            | SsaOp::Rethrow
            | SsaOp::Leave { .. }
            | SsaOp::EndFinally
            | SsaOp::EndFilter { .. }
            | SsaOp::BranchCmp { .. }
            | SsaOp::BranchFlags { .. } => {
                self.generate_branch_op(encoder, ssa, current_block_idx, op, next_block_idx)?;
            }

            // Simple standalone operations
            SsaOp::Pop { .. } => {
                encoder.emit_instruction("pop", None)?;
            }

            SsaOp::Nop => {
                encoder.emit_instruction("nop", None)?;
            }

            SsaOp::Break => {
                encoder.emit_instruction("break", None)?;
            }

            // Prefix instructions
            SsaOp::Constrained {
                constraint_type, ..
            } => {
                encoder.emit_instruction(
                    "constrained.",
                    Some(Operand::Token(constraint_type.token())),
                )?;
            }

            SsaOp::Volatile => {
                encoder.emit_instruction("volatile.", None)?;
            }

            SsaOp::Unaligned { alignment } => {
                encoder.emit_instruction(
                    "unaligned.",
                    Some(Operand::Immediate(Immediate::UInt8(*alignment))),
                )?;
            }

            SsaOp::TailPrefix => {
                encoder.emit_instruction("tail.", None)?;
            }

            SsaOp::Readonly => {
                encoder.emit_instruction("readonly.", None)?;
            }

            SsaOp::Phi { .. }
            | SsaOp::Fence { .. }
            | SsaOp::InterruptReturn
            | SsaOp::Unreachable => {
                // Phi nodes are eliminated during code generation - no instruction emitted
            }
            // Rotate and bit manipulation operations - not emitted as CIL primitives
            SsaOp::Rol { .. }
            | SsaOp::Ror { .. }
            | SsaOp::Rcl { .. }
            | SsaOp::Rcr { .. }
            | SsaOp::BSwap { .. }
            | SsaOp::BRev { .. }
            | SsaOp::BitScanForward { .. }
            | SsaOp::BitScanReverse { .. }
            | SsaOp::Popcount { .. }
            | SsaOp::Parity { .. }
            | SsaOp::Select { .. }
            | SsaOp::ReadFlags { .. }
            | SsaOp::CmpXchg { .. }
            | SsaOp::AtomicRmw { .. }
            // Native SSA substrate operations (wide arithmetic, native
            // boolean/float-flag ops, SIMD/vector, native atomics, bitcast,
            // opaque, indirect branch). These never appear in CIL-lifted SSA
            // and have no direct CIL encoding; enumerated explicitly (no
            // wildcard) so future substrate additions still trip this
            // exhaustiveness check.
            | SsaOp::WideMul { .. }
            | SsaOp::WideDiv { .. }
            | SsaOp::FloatCompareFlags { .. }
            | SsaOp::BoolAnd { .. }
            | SsaOp::BoolOr { .. }
            | SsaOp::BoolXor { .. }
            | SsaOp::BoolNot { .. }
            | SsaOp::Bitcast { .. }
            | SsaOp::IndirectBranch { .. }
            | SsaOp::NativeOpaque(_)
            | SsaOp::VectorUnary { .. }
            | SsaOp::VectorBinary { .. }
            | SsaOp::VectorTernary { .. }
            | SsaOp::VectorPredicatedUnary { .. }
            | SsaOp::VectorPredicatedBinary { .. }
            | SsaOp::VectorPredicatedTernary { .. }
            | SsaOp::VectorCompare { .. }
            | SsaOp::VectorLoad { .. }
            | SsaOp::VectorStore { .. }
            | SsaOp::VectorMaskedLoad { .. }
            | SsaOp::VectorMaskedStore { .. }
            | SsaOp::VectorBroadcastLoad { .. }
            | SsaOp::VectorGather { .. }
            | SsaOp::VectorFaultingLoad { .. }
            | SsaOp::VectorSegmentLoad { .. }
            | SsaOp::VectorScatter { .. }
            | SsaOp::VectorSegmentStore { .. }
            | SsaOp::VectorExtract { .. }
            | SsaOp::VectorInsert { .. }
            | SsaOp::VectorSplat { .. }
            | SsaOp::VectorShuffle { .. }
            | SsaOp::VectorCast { .. }
            | SsaOp::VectorReinterpret { .. }
            | SsaOp::VectorPack { .. }
            | SsaOp::VectorPackLoad { .. }
            | SsaOp::VectorPackStore { .. }
            | SsaOp::VectorZeroUpper { .. }
            | SsaOp::VectorMaskUnary { .. }
            | SsaOp::VectorMaskBinary { .. }
            | SsaOp::VectorReduce { .. }
            | SsaOp::VectorBitmask { .. }
            | SsaOp::AtomicLoad { .. }
            | SsaOp::AtomicStore { .. }
            | SsaOp::AtomicStoreConditional { .. }
            | SsaOp::AtomicPairLoad { .. }
            | SsaOp::AtomicPairStoreConditional { .. }
            | SsaOp::AtomicExchange { .. }
            | SsaOp::AtomicLockRmw { .. }
            | SsaOp::AtomicCmpXchg { .. }
            | SsaOp::AtomicPairCmpXchg { .. } => {
                // These operations may appear in the shared SSA but are not
                // directly expressible in CIL; they should have been lowered
                // before code generation.
            }
        }
        Ok(())
    }

    /// Generates CIL for arithmetic and bitwise operations.
    ///
    /// Handles: `Add`, `Sub`, `Mul`, `Div`, `Rem`, overflow-checked variants,
    /// `And`, `Or`, `Xor`, `Shl`, `Shr`, `Neg`, `Not`.
    /// Operands are already on the evaluation stack.
    fn generate_arithmetic_op(encoder: &mut InstructionEncoder, op: &SsaOp) -> Result<()> {
        match op {
            SsaOp::Add { dest, .. } => {
                encoder.emit_instruction("add", None)?;
                let _ = dest;
            }

            SsaOp::Sub { dest, .. } => {
                encoder.emit_instruction("sub", None)?;
                let _ = dest;
            }

            SsaOp::Mul { dest, .. } => {
                encoder.emit_instruction("mul", None)?;
                let _ = dest;
            }

            SsaOp::Div { dest, unsigned, .. } => {
                if *unsigned {
                    encoder.emit_instruction("div.un", None)?;
                } else {
                    encoder.emit_instruction("div", None)?;
                }
                let _ = dest;
            }

            SsaOp::Rem { dest, unsigned, .. } => {
                if *unsigned {
                    encoder.emit_instruction("rem.un", None)?;
                } else {
                    encoder.emit_instruction("rem", None)?;
                }
                let _ = dest;
            }

            SsaOp::AddOvf { dest, unsigned, .. } => {
                if *unsigned {
                    encoder.emit_instruction("add.ovf.un", None)?;
                } else {
                    encoder.emit_instruction("add.ovf", None)?;
                }
                let _ = dest;
            }

            SsaOp::SubOvf { dest, unsigned, .. } => {
                if *unsigned {
                    encoder.emit_instruction("sub.ovf.un", None)?;
                } else {
                    encoder.emit_instruction("sub.ovf", None)?;
                }
                let _ = dest;
            }

            SsaOp::MulOvf { dest, unsigned, .. } => {
                if *unsigned {
                    encoder.emit_instruction("mul.ovf.un", None)?;
                } else {
                    encoder.emit_instruction("mul.ovf", None)?;
                }
                let _ = dest;
            }

            SsaOp::And { dest, .. } => {
                encoder.emit_instruction("and", None)?;
                let _ = dest;
            }

            SsaOp::Or { dest, .. } => {
                encoder.emit_instruction("or", None)?;
                let _ = dest;
            }

            SsaOp::Xor { dest, .. } => {
                encoder.emit_instruction("xor", None)?;
                let _ = dest;
            }

            SsaOp::Shl { dest, .. } => {
                encoder.emit_instruction("shl", None)?;
                let _ = dest;
            }

            SsaOp::Shr { dest, unsigned, .. } => {
                if *unsigned {
                    encoder.emit_instruction("shr.un", None)?;
                } else {
                    encoder.emit_instruction("shr", None)?;
                }
                let _ = dest;
            }

            SsaOp::Neg { dest, .. } => {
                encoder.emit_instruction("neg", None)?;
                let _ = dest;
            }

            SsaOp::Not { dest, .. } => {
                encoder.emit_instruction("not", None)?;
                let _ = dest;
            }

            _ => unreachable!("generate_arithmetic_op called with non-arithmetic op"),
        }
        Ok(())
    }

    /// Generates CIL for comparison operations.
    ///
    /// Handles: `Ceq`, `Clt`, `Cgt` (and unsigned variants).
    /// Operands are already on the evaluation stack.
    fn generate_comparison_op(encoder: &mut InstructionEncoder, op: &SsaOp) -> Result<()> {
        match op {
            SsaOp::Ceq { dest, .. } => {
                encoder.emit_instruction("ceq", None)?;
                let _ = dest;
            }

            SsaOp::Clt { dest, unsigned, .. } => {
                if *unsigned {
                    encoder.emit_instruction("clt.un", None)?;
                } else {
                    encoder.emit_instruction("clt", None)?;
                }
                let _ = dest;
            }

            SsaOp::Cgt { dest, unsigned, .. } => {
                if *unsigned {
                    encoder.emit_instruction("cgt.un", None)?;
                } else {
                    encoder.emit_instruction("cgt", None)?;
                }
                let _ = dest;
            }

            _ => unreachable!("generate_comparison_op called with non-comparison op"),
        }
        Ok(())
    }

    /// Generates CIL for conversion operations.
    ///
    /// Handles: `Conv` (with overflow check and unsigned variants), `Ckfinite`.
    /// Operand is already on the evaluation stack.
    fn generate_conversion_op(encoder: &mut InstructionEncoder, op: &SsaOp) -> Result<()> {
        match op {
            SsaOp::Conv {
                dest,
                target,
                overflow_check,
                unsigned,
                ..
            } => {
                // Operand already on stack
                emitter::emit_conv(encoder, target, *overflow_check, *unsigned)?;
                let _ = dest;
            }

            SsaOp::Ckfinite { dest, .. } => {
                encoder.emit_instruction("ckfinite", None)?;
                let _ = dest;
            }

            _ => unreachable!("generate_conversion_op called with non-conversion op"),
        }
        Ok(())
    }

    /// Generates CIL for call operations.
    ///
    /// Handles: `Call`, `CallVirt`, `CallIndirect`, `NewObj`.
    /// Arguments are already on the evaluation stack.
    fn generate_call_op(encoder: &mut InstructionEncoder, op: &SsaOp) -> Result<()> {
        match op {
            SsaOp::Call { dest, method, args } => {
                // num_args: the method arguments that were pushed on stack
                let num_args = u8::try_from(args.len()).unwrap_or(u8::MAX);
                let has_result = dest.is_some();
                encoder.emit_call(
                    "call",
                    Some(Operand::Token(method.token())),
                    num_args,
                    has_result,
                )?;
                // Result left on stack - handled by caller
                let _ = dest;
            }

            SsaOp::CallVirt { dest, method, args } => {
                // num_args: the method arguments that were pushed on stack
                let num_args = u8::try_from(args.len()).unwrap_or(u8::MAX);
                let has_result = dest.is_some();
                encoder.emit_call(
                    "callvirt",
                    Some(Operand::Token(method.token())),
                    num_args,
                    has_result,
                )?;
                let _ = dest;
            }

            SsaOp::CallIndirect {
                dest,
                signature,
                args,
                ..
            } => {
                // num_args: function pointer + the method arguments
                let num_args = u8::try_from(args.len().saturating_add(1)).unwrap_or(u8::MAX);
                let has_result = dest.is_some();
                encoder.emit_call(
                    "calli",
                    Some(Operand::Token(signature.token())),
                    num_args,
                    has_result,
                )?;
                let _ = dest;
            }

            SsaOp::NewObj { dest, ctor, args } => {
                // num_args: constructor arguments (newobj always returns the new object)
                let num_args = u8::try_from(args.len()).unwrap_or(u8::MAX);
                encoder.emit_call("newobj", Some(Operand::Token(ctor.token())), num_args, true)?;
                let _ = dest;
            }

            _ => unreachable!("generate_call_op called with non-call op"),
        }
        Ok(())
    }

    /// Generates CIL for load, store, and memory operations.
    ///
    /// Handles field access (`LoadField`, `StoreField`, `LoadStaticField`, etc.),
    /// element access (`LoadElement`, `StoreElement`, `LoadElementAddr`),
    /// local/arg access (`LoadArg`, `LoadLocal`, `LoadArgAddr`, `LoadLocalAddr`),
    /// object operations (`Box`, `Unbox`, `CastClass`, `IsInst`, `NewArr`, etc.),
    /// indirect access (`LoadIndirect`, `StoreIndirect`, `LoadObj`, `StoreObj`),
    /// block operations (`InitBlk`, `CopyBlk`, `CopyObj`), and `Copy`.
    fn generate_load_store_op(
        &mut self,
        encoder: &mut InstructionEncoder,
        ssa: &SsaFunction,
        op: &SsaOp,
    ) -> Result<()> {
        match op {
            SsaOp::Copy { dest, src } => {
                // Copy instruction: src is loaded by scheduler via get_operands_in_stack_order.
                // We just need to emit the store to dest's location.
                // Note: Copy instructions where src and dest have the same storage
                // are filtered out earlier (in generate_block_instructions), so we
                // always need to do the store here.
                let dest_storage = self.get_or_allocate_storage(ssa, *dest)?;
                match dest_storage {
                    VarStorage::Local(idx) => {
                        self.used_locals.insert(idx);
                        emitter::emit_stloc(encoder, idx)?;
                    }
                    VarStorage::Arg(idx) => emitter::emit_starg(encoder, idx)?,
                    VarStorage::Stack => {
                        // Can't store to stack, value already there
                    }
                }
                let _ = src;
            }
            SsaOp::LoadField { dest, field, .. } => {
                // object is loaded by scheduler via get_operands_in_stack_order
                encoder.emit_instruction("ldfld", Some(Operand::Token(field.token())))?;
                let _ = dest;
            }
            SsaOp::StoreField { field, .. } => {
                // object and value are loaded by scheduler via get_operands_in_stack_order
                encoder.emit_instruction("stfld", Some(Operand::Token(field.token())))?;
            }

            SsaOp::LoadStaticField { dest, field } => {
                encoder.emit_instruction("ldsfld", Some(Operand::Token(field.token())))?;
                let _ = dest;
            }

            SsaOp::StoreStaticField { field, .. } => {
                // value is loaded by scheduler via get_operands_in_stack_order
                encoder.emit_instruction("stsfld", Some(Operand::Token(field.token())))?;
            }
            SsaOp::LoadElement {
                dest, elem_type, ..
            } => {
                // array and index are loaded by scheduler via get_operands_in_stack_order
                emitter::emit_ldelem(encoder, elem_type)?;
                let _ = dest;
            }
            SsaOp::StoreElement { elem_type, .. } => {
                // array, index, and value are loaded by scheduler via get_operands_in_stack_order
                emitter::emit_stelem(encoder, elem_type)?;
            }
            SsaOp::ArrayLength { dest, .. } => {
                // array is loaded by scheduler via get_operands_in_stack_order
                encoder.emit_instruction("ldlen", None)?;
                let _ = dest;
            }

            SsaOp::NewArr {
                dest, elem_type, ..
            } => {
                // length is loaded by scheduler via get_operands_in_stack_order
                encoder.emit_instruction("newarr", Some(Operand::Token(elem_type.token())))?;
                let _ = dest;
            }
            SsaOp::Box {
                dest, value_type, ..
            } => {
                // value is loaded by scheduler via get_operands_in_stack_order
                encoder.emit_instruction("box", Some(Operand::Token(value_type.token())))?;
                let _ = dest;
            }

            SsaOp::Unbox {
                dest, value_type, ..
            } => {
                // object is loaded by scheduler via get_operands_in_stack_order
                encoder.emit_instruction("unbox", Some(Operand::Token(value_type.token())))?;
                let _ = dest;
            }
            SsaOp::UnboxAny {
                dest, value_type, ..
            } => {
                // object is loaded by scheduler via get_operands_in_stack_order
                encoder.emit_instruction("unbox.any", Some(Operand::Token(value_type.token())))?;
                let _ = dest;
            }
            SsaOp::CastClass {
                dest, target_type, ..
            } => {
                // object is loaded by scheduler via get_operands_in_stack_order
                encoder.emit_instruction("castclass", Some(Operand::Token(target_type.token())))?;
                let _ = dest;
            }
            SsaOp::IsInst {
                dest, target_type, ..
            } => {
                // object is loaded by scheduler via get_operands_in_stack_order
                encoder.emit_instruction("isinst", Some(Operand::Token(target_type.token())))?;
                let _ = dest;
            }

            SsaOp::SizeOf { dest, value_type } => {
                encoder.emit_instruction("sizeof", Some(Operand::Token(value_type.token())))?;
                let _ = dest;
            }

            SsaOp::LoadToken { dest, token } => {
                encoder.emit_instruction("ldtoken", Some(Operand::Token(token.token())))?;
                let _ = dest;
            }

            SsaOp::LoadArg { dest, arg_index } => {
                emitter::emit_ldarg(encoder, *arg_index)?;
                let _ = dest;
            }

            SsaOp::LoadLocal { dest, local_index } => {
                let actual_index = self
                    .original_to_compacted
                    .get(local_index)
                    .copied()
                    .unwrap_or(*local_index);
                self.used_locals.insert(actual_index);
                emitter::emit_ldloc(encoder, actual_index)?;
                let _ = dest;
            }

            SsaOp::LoadArgAddr { dest, arg_index } => {
                emitter::emit_ldarga(encoder, *arg_index)?;
                let _ = dest;
            }

            SsaOp::LoadLocalAddr { dest, local_index } => {
                let actual_index = self
                    .original_to_compacted
                    .get(local_index)
                    .copied()
                    .unwrap_or(*local_index);
                self.used_locals.insert(actual_index);
                emitter::emit_ldloca(encoder, actual_index)?;
                let _ = dest;
            }

            SsaOp::LoadFieldAddr { dest, field, .. } => {
                encoder.emit_instruction("ldflda", Some(Operand::Token(field.token())))?;
                let _ = dest;
            }

            SsaOp::LoadStaticFieldAddr { dest, field } => {
                encoder.emit_instruction("ldsflda", Some(Operand::Token(field.token())))?;
                let _ = dest;
            }

            SsaOp::LoadFunctionPtr { dest, method } => {
                encoder.emit_instruction("ldftn", Some(Operand::Token(method.token())))?;
                let _ = dest;
            }

            SsaOp::LoadVirtFunctionPtr { dest, method, .. } => {
                encoder.emit_instruction("ldvirtftn", Some(Operand::Token(method.token())))?;
                let _ = dest;
            }

            SsaOp::LocalAlloc { dest, .. } => {
                encoder.emit_instruction("localloc", None)?;
                let _ = dest;
            }

            SsaOp::InitObj { value_type, .. } => {
                encoder.emit_instruction("initobj", Some(Operand::Token(value_type.token())))?;
            }

            SsaOp::LoadObj {
                dest, value_type, ..
            } => {
                encoder.emit_instruction("ldobj", Some(Operand::Token(value_type.token())))?;
                let _ = dest;
            }

            SsaOp::StoreObj { value_type, .. } => {
                encoder.emit_instruction("stobj", Some(Operand::Token(value_type.token())))?;
            }

            SsaOp::LoadIndirect {
                dest, value_type, ..
            } => {
                let mnemonic = match value_type {
                    SsaType::I8 => "ldind.i1",
                    SsaType::U8 => "ldind.u1",
                    SsaType::I16 => "ldind.i2",
                    SsaType::U16 => "ldind.u2",
                    SsaType::U32 => "ldind.u4",
                    SsaType::I64 | SsaType::U64 => "ldind.i8",
                    SsaType::F32 => "ldind.r4",
                    SsaType::F64 => "ldind.r8",
                    SsaType::NativeInt | SsaType::NativeUInt => "ldind.i",
                    SsaType::Object => "ldind.ref",
                    _ => "ldind.i4", // I32 and other types default to i4
                };
                encoder.emit_instruction(mnemonic, None)?;
                let _ = dest;
            }

            SsaOp::StoreIndirect { value_type, .. } => {
                let mnemonic = match value_type {
                    SsaType::I8 | SsaType::U8 => "stind.i1",
                    SsaType::I16 | SsaType::U16 => "stind.i2",
                    SsaType::I64 | SsaType::U64 => "stind.i8",
                    SsaType::F32 => "stind.r4",
                    SsaType::F64 => "stind.r8",
                    SsaType::NativeInt | SsaType::NativeUInt => "stind.i",
                    SsaType::Object => "stind.ref",
                    _ => "stind.i4", // I32, U32, and other types default to i4
                };
                encoder.emit_instruction(mnemonic, None)?;
            }

            SsaOp::LoadElementAddr {
                dest, elem_type, ..
            } => {
                encoder.emit_instruction("ldelema", Some(Operand::Token(elem_type.token())))?;
                let _ = dest;
            }

            SsaOp::InitBlk { .. } => {
                encoder.emit_instruction("initblk", None)?;
            }

            SsaOp::CopyBlk { .. } => {
                encoder.emit_instruction("cpblk", None)?;
            }

            SsaOp::CopyObj { value_type, .. } => {
                encoder.emit_instruction("cpobj", Some(Operand::Token(value_type.token())))?;
            }

            _ => unreachable!("generate_load_store_op called with non-load/store op"),
        }
        Ok(())
    }

    /// Generates CIL for branch and control flow operations.
    ///
    /// Handles: `Return`, `Jump`, `Branch`, `Switch`, `Throw`, `Rethrow`,
    /// `Leave`, `EndFinally`, `EndFilter`, `BranchCmp`.
    /// Spills remaining stack values before control flow transfer and emits
    /// phi stores for successor blocks as needed.
    fn generate_branch_op(
        &mut self,
        encoder: &mut InstructionEncoder,
        ssa: &SsaFunction,
        current_block_idx: usize,
        op: &SsaOp,
        next_block_idx: Option<usize>,
    ) -> Result<()> {
        match op {
            SsaOp::Return { .. } => {
                // Spill any remaining stack values before return.
                // The return value (if any) is already on the stack from operand loading.
                // We need to spill OTHER values that might be lingering on stack_vars.
                //
                // Note: If there's a return value, it's already been consumed from stack_vars
                // during operand loading, so spilling here won't affect it.
                self.spill_stack(encoder, ssa)?;

                encoder.emit_instruction("ret", None)?;
            }

            SsaOp::Jump { target } => {
                // Spill remaining stack values before control flow transfer
                self.spill_stack(encoder, ssa)?;

                // Emit phi stores for the target block before jumping
                self.emit_phi_stores_for_successor(encoder, ssa, current_block_idx, *target)?;

                if Some(*target) != next_block_idx {
                    let label = self
                        .block_labels
                        .get(target)
                        .cloned()
                        .unwrap_or_else(|| format!("block_{target}"));
                    // emit_branch validates stack depth at target
                    encoder.emit_branch("br", &label)?;
                }
            }

            SsaOp::Branch {
                true_target,
                false_target,
                ..
            } => {
                // Spill any remaining stack values except the condition.
                // The condition is already on the stack from operand loading.
                self.spill_stack(encoder, ssa)?;

                // Handle phi stores for both targets using intermediate blocks
                self.emit_branch_with_phi_stores(
                    encoder,
                    ssa,
                    current_block_idx,
                    *true_target,
                    *false_target,
                    next_block_idx,
                )?;
            }

            SsaOp::Switch {
                targets, default, ..
            } => {
                // Spill any remaining stack values except the switch value.
                self.spill_stack(encoder, ssa)?;

                // Handle phi stores for switch targets using intermediate blocks
                self.emit_switch_with_phi_stores(
                    encoder,
                    ssa,
                    current_block_idx,
                    targets,
                    *default,
                    next_block_idx,
                )?;
            }

            SsaOp::Throw { .. } => {
                // Spill any remaining stack values except the exception.
                self.spill_stack(encoder, ssa)?;

                encoder.emit_instruction("throw", None)?;
            }

            SsaOp::Rethrow => {
                // Spill any remaining stack values.
                self.spill_stack(encoder, ssa)?;

                encoder.emit_instruction("rethrow", None)?;
            }

            SsaOp::Leave { target } => {
                // Spill any remaining stack values before leaving protected region.
                self.spill_stack(encoder, ssa)?;

                // Emit phi stores for the target block before leaving
                self.emit_phi_stores_for_successor(encoder, ssa, current_block_idx, *target)?;

                let label = self
                    .block_labels
                    .get(target)
                    .cloned()
                    .unwrap_or_else(|| format!("block_{target}"));
                encoder.emit_branch("leave", &label)?;
            }

            SsaOp::EndFinally => {
                // Spill any remaining stack values.
                self.spill_stack(encoder, ssa)?;

                encoder.emit_instruction("endfinally", None)?;
            }

            SsaOp::EndFilter { .. } => {
                // Spill any remaining stack values except the filter result.
                self.spill_stack(encoder, ssa)?;

                encoder.emit_instruction("endfilter", None)?;
            }

            SsaOp::BranchCmp {
                cmp,
                unsigned,
                true_target,
                false_target,
                ..
            } => {
                // Spill any remaining stack values except the comparison operands.
                self.spill_stack(encoder, ssa)?;

                // Emit comparison branch with phi stores - operands are already on the stack
                self.emit_branch_cmp_with_phi_stores(
                    encoder,
                    ssa,
                    current_block_idx,
                    *cmp,
                    *unsigned,
                    *true_target,
                    *false_target,
                    next_block_idx,
                )?;
            }

            _ => unreachable!("generate_branch_op called with non-branch op"),
        }
        Ok(())
    }

    /// Gets the operands of an operation in the order they should appear on the stack.
    ///
    /// For CIL stack-based operations, operands are consumed in a specific order.
    /// This method returns operands in that order so scheduling can ensure
    /// the correct stack layout.
    #[allow(clippy::match_same_arms)] // Arms intentionally separate for semantic clarity
    fn get_operands_in_stack_order(op: &SsaOp) -> Vec<SsaVarId> {
        match op {
            // Binary operations: left on stack bottom, right on top
            SsaOp::Add { left, right, .. }
            | SsaOp::AddOvf { left, right, .. }
            | SsaOp::Sub { left, right, .. }
            | SsaOp::SubOvf { left, right, .. }
            | SsaOp::Mul { left, right, .. }
            | SsaOp::MulOvf { left, right, .. }
            | SsaOp::Div { left, right, .. }
            | SsaOp::Rem { left, right, .. }
            | SsaOp::And { left, right, .. }
            | SsaOp::Or { left, right, .. }
            | SsaOp::Xor { left, right, .. }
            | SsaOp::Ceq { left, right, .. }
            | SsaOp::Clt { left, right, .. }
            | SsaOp::Cgt { left, right, .. } => vec![*left, *right],

            // Shift operations: value on bottom, amount on top
            SsaOp::Shl { value, amount, .. } | SsaOp::Shr { value, amount, .. } => {
                vec![*value, *amount]
            }

            // Unary operations: single operand
            SsaOp::Neg { operand, .. }
            | SsaOp::Not { operand, .. }
            | SsaOp::Conv { operand, .. }
            | SsaOp::Ckfinite { operand, .. } => vec![*operand],

            // Return with value
            SsaOp::Return { value: Some(v) } => vec![*v],

            // Branch condition
            SsaOp::Branch { condition, .. } => vec![*condition],

            // BranchCmp: left and right operands
            SsaOp::BranchCmp { left, right, .. } => vec![*left, *right],

            // Throw exception
            SsaOp::Throw { exception } => vec![*exception],

            // Pop value
            SsaOp::Pop { value } => vec![*value],

            // Switch value
            SsaOp::Switch { value, .. } => vec![*value],

            // Store operations: object first (if present), then value
            SsaOp::StoreField { object, value, .. } => vec![*object, *value],

            SsaOp::StoreStaticField { value, .. } => vec![*value],

            // Store element: array, index, then value
            SsaOp::StoreElement {
                array,
                index,
                value,
                ..
            } => vec![*array, *index, *value],

            // Load element: array first, then index
            SsaOp::LoadElement { array, index, .. }
            | SsaOp::LoadElementAddr { array, index, .. } => vec![*array, *index],

            // Array length
            SsaOp::ArrayLength { array, .. } => vec![*array],

            // Load field: object reference
            SsaOp::LoadField { object, .. } | SsaOp::LoadFieldAddr { object, .. } => vec![*object],

            // New array: length
            SsaOp::NewArr { length, .. } => vec![*length],

            // Boxing/unboxing operations
            SsaOp::Box { value, .. } => vec![*value],
            SsaOp::Unbox { object, .. }
            | SsaOp::UnboxAny { object, .. }
            | SsaOp::CastClass { object, .. }
            | SsaOp::IsInst { object, .. } => vec![*object],

            // Copy operation
            SsaOp::Copy { src, .. } => vec![*src],

            // Local allocation
            SsaOp::LocalAlloc { size, .. } => vec![*size],

            // Virtual function pointer
            SsaOp::LoadVirtFunctionPtr { object, .. } => vec![*object],

            // Object operations
            SsaOp::InitObj { dest_addr, .. } => vec![*dest_addr],
            SsaOp::LoadObj { src_addr, .. } => vec![*src_addr],
            SsaOp::StoreObj {
                dest_addr, value, ..
            } => vec![*dest_addr, *value],
            SsaOp::CopyObj {
                dest_addr,
                src_addr,
                ..
            } => vec![*dest_addr, *src_addr],

            // Indirect memory operations
            SsaOp::LoadIndirect { addr, .. } => vec![*addr],
            SsaOp::StoreIndirect { addr, value, .. } => vec![*addr, *value],

            // Block memory operations
            SsaOp::InitBlk {
                dest_addr,
                value,
                size,
            } => vec![*dest_addr, *value, *size],
            SsaOp::CopyBlk {
                dest_addr,
                src_addr,
                size,
            } => vec![*dest_addr, *src_addr, *size],

            // Exception handling
            SsaOp::EndFilter { result } => vec![*result],

            // Call operations: use the op's uses() method
            SsaOp::Call { .. }
            | SsaOp::CallVirt { .. }
            | SsaOp::CallIndirect { .. }
            | SsaOp::NewObj { .. } => op.uses(),

            // Operations with no operands or operands from outside the block
            _ => Vec::new(),
        }
    }

    /// Checks if an operation is a terminator (control flow instruction).
    fn is_terminator(op: &SsaOp) -> bool {
        matches!(
            op,
            SsaOp::Jump { .. }
                | SsaOp::Branch { .. }
                | SsaOp::BranchCmp { .. }
                | SsaOp::Switch { .. }
                | SsaOp::Return { .. }
                | SsaOp::Throw { .. }
                | SsaOp::Rethrow
                | SsaOp::Leave { .. }
                | SsaOp::EndFinally
                | SsaOp::EndFilter { .. }
        )
    }

    /// Loads a constant value onto the stack.
    ///
    /// Uses optimized CIL instructions where possible (ldc.i4.0 through ldc.i4.8,
    /// ldc.i4.s for small values, etc.).
    fn generate_const(&self, encoder: &mut InstructionEncoder, value: &ConstValue) -> Result<()> {
        match value {
            // 8-bit signed integers use ldc.i4.s (sign-extends to i32)
            ConstValue::I8(v) => {
                encoder
                    .emit_instruction("ldc.i4.s", Some(Operand::Immediate(Immediate::Int8(*v))))?;
            }

            // 8-bit unsigned integers: use ldc.i4.s only if value fits in signed byte,
            // otherwise use ldc.i4 to avoid incorrect sign extension
            ConstValue::U8(v) => {
                if *v <= 127 {
                    encoder.emit_instruction(
                        "ldc.i4.s",
                        Some(Operand::Immediate(Immediate::Int8((*v).cast_signed()))),
                    )?;
                } else {
                    // Value > 127 would be sign-extended incorrectly by ldc.i4.s
                    encoder.emit_instruction(
                        "ldc.i4",
                        Some(Operand::Immediate(Immediate::Int32(i32::from(*v)))),
                    )?;
                }
            }

            // 16-bit integers widen to i32 for ldc.i4
            ConstValue::I16(v) => {
                encoder.emit_instruction(
                    "ldc.i4",
                    Some(Operand::Immediate(Immediate::Int32(i32::from(*v)))),
                )?;
            }

            ConstValue::U16(v) => {
                encoder.emit_instruction(
                    "ldc.i4",
                    Some(Operand::Immediate(Immediate::Int32(i32::from(*v)))),
                )?;
            }

            // 32-bit signed integers have optimized forms for common values
            ConstValue::I32(v) => {
                emitter::emit_ldc_i4(encoder, *v)?;
            }

            // 32-bit unsigned uses TryFrom (bit-preserving cast to Int32)
            ConstValue::U32(_) => {
                encoder.emit_instruction(
                    "ldc.i4",
                    Some(Operand::Immediate(Immediate::try_from(value)?)),
                )?;
            }

            // 64-bit integers (signed and unsigned) use ldc.i8
            ConstValue::I64(_) | ConstValue::U64(_) => {
                encoder.emit_instruction(
                    "ldc.i8",
                    Some(Operand::Immediate(Immediate::try_from(value)?)),
                )?;
            }

            // Native integers need conv.i/conv.u after loading
            ConstValue::NativeInt(_) => {
                encoder.emit_instruction(
                    "ldc.i8",
                    Some(Operand::Immediate(Immediate::try_from(value)?)),
                )?;
                encoder.emit_instruction("conv.i", None)?;
            }

            ConstValue::NativeUInt(_) => {
                encoder.emit_instruction(
                    "ldc.i8",
                    Some(Operand::Immediate(Immediate::try_from(value)?)),
                )?;
                encoder.emit_instruction("conv.u", None)?;
            }

            // Floating point
            ConstValue::F32(_) => {
                encoder.emit_instruction(
                    "ldc.r4",
                    Some(Operand::Immediate(Immediate::try_from(value)?)),
                )?;
            }

            ConstValue::F64(_) => {
                encoder.emit_instruction(
                    "ldc.r8",
                    Some(Operand::Immediate(Immediate::try_from(value)?)),
                )?;
            }

            // String constants reference the user string heap
            ConstValue::String(idx) => {
                let token = Token::new(0x7000_0000 | *idx);
                encoder.emit_instruction("ldstr", Some(Operand::Token(token)))?;
            }

            // Decrypted strings look up pre-interned index
            ConstValue::DecryptedString(s) => {
                if let Some(&idx) = self.interned_strings.get(s.as_ref()) {
                    let token = Token::new(0x7000_0000 | idx);
                    encoder.emit_instruction("ldstr", Some(Operand::Token(token)))?;
                } else {
                    // String wasn't pre-interned - fall back to ldnull
                    encoder.emit_instruction("ldnull", None)?;
                }
            }

            // Null reference
            ConstValue::Null => {
                encoder.emit_instruction("ldnull", None)?;
            }

            // Booleans use optimized ldc.i4.1/ldc.i4.0
            ConstValue::True => {
                encoder.emit_instruction("ldc.i4.1", None)?;
            }

            ConstValue::False => {
                encoder.emit_instruction("ldc.i4.0", None)?;
            }

            // Runtime handles use ldtoken
            ConstValue::Type(type_ref) => {
                encoder.emit_instruction("ldtoken", Some(Operand::Token(type_ref.token())))?;
            }

            ConstValue::MethodHandle(method_ref) => {
                encoder.emit_instruction("ldtoken", Some(Operand::Token(method_ref.token())))?;
            }

            ConstValue::FieldHandle(field_ref) => {
                encoder.emit_instruction("ldtoken", Some(Operand::Token(field_ref.token())))?;
            }

            // Decrypted arrays: emit newarr + individual element stores.
            // Decrypted arrays: emit newarr + InitializeArray using FieldRVA data.
            // Produces the same compact pattern as the C# compiler:
            //   ldc.i4 <num_elements>
            //   newarr <element_type>      ; push array (+1)
            //   dup                        ; push copy (+2)
            //   ldtoken <field_with_rva>   ; push handle (+3)
            //   call InitializeArray       ; pop 2 (+1) — net: 1 value on stack
            ConstValue::DecryptedArray(arr) => {
                let elem_size = arr.element_size.max(1);
                #[allow(clippy::cast_possible_truncation)]
                let num_elements = arr.data.len().checked_div(elem_size).unwrap_or(0);

                emitter::emit_ldc_i4(encoder, num_elements as i32)?;
                encoder.emit_instruction(
                    "newarr",
                    Some(Operand::Token(arr.element_type_ref.token())),
                )?;

                if let Some(info) = self.interned_arrays.get(&arr.data) {
                    // Compact: dup + ldtoken + call InitializeArray
                    // Stack: [array] → [array, array] → [array, array, handle] → [array]
                    encoder.emit_instruction("dup", None)?;
                    encoder.emit_instruction("ldtoken", Some(Operand::Token(info.field_token)))?;

                    // InitializeArray(Array, RuntimeFieldHandle) → void: pops 2, pushes 0
                    encoder.emit_call(
                        "call",
                        Some(Operand::Token(info.initialize_array_token)),
                        2,
                        false,
                    )?;
                }
                // If interning failed, array is left uninitialized (zeroed).
                // This is still valid IL — the values will just be default(T).
            }

            // SIMD vector constants come from the native SSA substrate and have
            // no direct CIL `ldc`-style encoding.
            ConstValue::Vector(_) => {
                return Err(Error::CodegenFailed(
                    "Vector constants are not supported in CIL code generation".to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Emits a load instruction for an SSA variable (argument, local, or stack).
    ///
    /// This method implements dup optimization: if we're loading the same storage
    /// location that was just loaded, we emit `dup` instead of another load.
    /// This saves code size (dup is 1 byte vs 2-4 bytes for ldloc/ldarg).
    fn load_var(
        &mut self,
        encoder: &mut InstructionEncoder,
        ssa: &SsaFunction,
        var: SsaVarId,
    ) -> Result<()> {
        // Check if the variable is on the stack (from optimization)
        // Check if this is a deferred constant that should be generated inline
        if let Some(value) = self.deferred_constants.remove(&var) {
            // Generate the constant inline instead of loading from storage
            self.generate_const(encoder, &value)?;
            self.last_load = None;
            return Ok(());
        }

        // Only use stack optimization if the variable is on TOP of the tracked stack.
        // Variables anywhere else in stack_vars have been "buried" by subsequent values.
        if let Some(last) = self.stack_vars.last() {
            if *last == var {
                // Value is on top of the stack - no load needed
                self.stack_vars.pop();
                self.last_load = None;
                return Ok(());
            }
        }

        // If we're about to push a new value and there are stack_vars values that
        // will be buried, we need to save them first so they can be loaded later.
        // This handles the case where a single-use value was left on the stack but
        // other operands need to be loaded first.
        while let Some(buried_var) = self.stack_vars.pop() {
            // Get or force-allocate storage for the buried variable.
            // We use force_allocate_storage here because the variable MUST be
            // stored to a local - it's being buried and will need to be loaded later.
            // This handles stack_locals that unexpectedly need real storage.
            let storage = self.force_allocate_storage(ssa, buried_var)?;
            match storage {
                VarStorage::Local(idx) => {
                    self.used_locals.insert(idx);
                    emitter::emit_stloc(encoder, idx)?;
                }
                VarStorage::Arg(idx) => emitter::emit_starg(encoder, idx)?,
                VarStorage::Stack => {
                    // This should not happen with force_allocate_storage
                    return Err(Error::Deobfuscation(format!(
                        "load_var: buried variable {buried_var:?} still has Stack storage after force allocation - this indicates a bug"
                    )));
                }
            }
        }

        // Check if this variable is defined by a Const but wasn't deferred.
        // This handles constants that are used multiple times or defined in
        // non-dominating blocks (e.g., constants defined in initialization
        // paths that are used in loop back-edges).
        if !self.var_storage.contains_key(&var) {
            if let Some(SsaOp::Const { value, .. }) = ssa.get_definition(var) {
                self.generate_const(encoder, value)?;
                self.last_load = None;
                return Ok(());
            }
        }

        let storage = self.get_storage(var, ssa)?;

        // Dup optimization: if we're loading the same location we just loaded,
        // emit dup instead. This works because the previous value is still on
        // the stack and we can duplicate it.
        if self.last_load == Some(storage) {
            encoder.emit_instruction("dup", None)?;
            // Keep last_load the same - the duplicated value is conceptually
            // the same as the original, so another dup would still be valid
            return Ok(());
        }

        // Emit the actual load and track it
        match storage {
            VarStorage::Arg(idx) => {
                emitter::emit_ldarg(encoder, idx)?;
                self.last_load = Some(storage);
            }
            VarStorage::Local(idx) => {
                self.used_locals.insert(idx);
                emitter::emit_ldloc(encoder, idx)?;
                self.last_load = Some(storage);
            }
            VarStorage::Stack => {
                // This happens when a variable was identified as a stack_local
                // (expected to be consumed immediately after definition), but
                // we're trying to load it in a different context. The value
                // should already be on the stack from the producer operation.
                self.last_load = None;
            }
        }
        Ok(())
    }

    /// Emits a store instruction for an SSA variable (argument or local).
    ///
    /// This also clears the `last_load` tracking since a store consumes the top of
    /// the stack, invalidating any previous load state used for dup optimization.
    fn store_var(
        &mut self,
        encoder: &mut InstructionEncoder,
        ssa: &SsaFunction,
        var: SsaVarId,
    ) -> Result<()> {
        // A store consumes the top of the stack, so clear last_load to prevent
        // incorrect dup optimizations. Without this, sequences like:
        //   load X, store Y, load X
        // would incorrectly emit: ldloc.X, stloc.Y, dup
        // when they should emit: ldloc.X, stloc.Y, ldloc.X
        self.last_load = None;

        // Use get_or_allocate_storage to ensure we have a valid slot.
        // This handles the case where a variable doesn't have pre-allocated storage
        // (e.g., a deferred constant that got buried and needs to be stored).
        let storage = self.get_or_allocate_storage(ssa, var)?;

        match storage {
            VarStorage::Arg(idx) => emitter::emit_starg(encoder, idx),
            VarStorage::Local(idx) => {
                self.used_locals.insert(idx);
                emitter::emit_stloc(encoder, idx)
            }
            VarStorage::Stack => {
                // Should not happen - can't store to stack
                Ok(())
            }
        }
    }

    /// Spills all values currently on the stack to local variables.
    ///
    /// This must be called before any control flow instruction (branch, jump, switch,
    /// return, throw, leave) to ensure the stack is at a consistent depth at block
    /// boundaries. All paths to a label must have the same stack depth.
    ///
    /// Values in `stack_vars` are stored to their allocated local slots. This ensures
    /// they can be loaded again if needed in successor blocks.
    fn spill_stack(&mut self, encoder: &mut InstructionEncoder, ssa: &SsaFunction) -> Result<()> {
        // Store all tracked stack values to locals, in order (bottom to top)
        // so the stores happen in the correct stack order.
        while let Some(var) = self.stack_vars.pop() {
            // Use force_allocate_storage instead of get_or_allocate_storage.
            // This handles the case where a variable was identified as a stack_local
            // (expected to be consumed before any spill) but actually needs to be
            // spilled due to control flow (e.g., terminator before consumer).
            let storage = self.force_allocate_storage(ssa, var)?;
            match storage {
                VarStorage::Local(idx) => {
                    self.used_locals.insert(idx);
                    emitter::emit_stloc(encoder, idx)?;
                }
                VarStorage::Arg(idx) => emitter::emit_starg(encoder, idx)?,
                VarStorage::Stack => {
                    // Should never happen with force_allocate_storage
                    return Err(Error::Deobfuscation(format!(
                        "spill_stack: variable {var:?} still has Stack storage after force allocation - this indicates a bug"
                    )));
                }
            }
        }
        self.last_load = None;
        Ok(())
    }

    /// Allocates a temporary local slot, reusing from the pool if available.
    ///
    /// This is used for phi copy temporaries and other short-lived values.
    /// When the temporary is no longer needed, call `release_temp_local` to
    /// return it to the pool for reuse.
    fn allocate_temp_local(&mut self, var_type: &SsaType) -> u16 {
        // Try to reuse a pooled slot of the same type
        if let Some(slot) = self.temp_pool.try_allocate(var_type) {
            return slot;
        }

        // No pooled slot available - allocate a fresh one
        let slot = self.next_local;
        self.next_local = self.next_local.saturating_add(1);
        self.local_types.insert(slot, var_type.clone());
        slot
    }

    /// Releases a temporary local slot back to the pool for reuse.
    fn release_temp_local(&mut self, slot: u16, var_type: &SsaType) {
        self.temp_pool.release(slot, var_type.clone());
    }

    /// Checks if a successor block has phi nodes with operands from the current block.
    ///
    /// # Errors
    ///
    /// Returns an error if storage cannot be found for phi variables, indicating
    /// a bug in SSA construction.
    fn successor_has_phi_from(
        &self,
        ssa: &SsaFunction,
        current_block: usize,
        successor: usize,
    ) -> Result<bool> {
        let Some(succ_block) = ssa.block(successor) else {
            return Ok(false);
        };

        for phi in succ_block.phi_nodes() {
            if let Some(operand) = phi.operand_from(current_block) {
                // Skip dead phi results (not used by any instructions).
                // These are not pre-allocated during storage allocation.
                let phi_result = phi.result();
                let use_count = self
                    .global_use_counts
                    .get(&phi_result)
                    .copied()
                    .unwrap_or(0);
                if use_count == 0 {
                    continue;
                }

                // Check if phi store would actually do something.
                // IMPORTANT: If the operand doesn't have actual storage (e.g., a constant
                // defined in a non-dominating block), we need phi stores.
                let operand_has_storage = self.var_storage.contains_key(&operand.value());
                if !operand_has_storage {
                    // Operand has no storage - we need to emit it (constant inline)
                    return Ok(true);
                }
                let operand_storage = self.get_storage(operand.value(), ssa)?;
                let result_storage = self.get_storage(phi_result, ssa)?;
                if operand_storage != result_storage {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Emits a conditional branch (brtrue/brfalse) with proper phi store handling.
    ///
    /// When branch targets have phi nodes, we emit intermediate blocks that:
    /// 1. Execute the phi stores for that specific edge
    /// 2. Jump to the actual target
    ///
    /// This handles the "critical edge splitting" problem where different predecessors
    /// need to provide different values to phi nodes.
    fn emit_branch_with_phi_stores(
        &mut self,
        encoder: &mut InstructionEncoder,
        ssa: &SsaFunction,
        current_block_idx: usize,
        true_target: usize,
        false_target: usize,
        next_block_idx: Option<usize>,
    ) -> Result<()> {
        // Same-target: condition is irrelevant, discard it and emit unconditional branch
        if true_target == false_target {
            encoder.emit_instruction("pop", None)?;
            if self.successor_has_phi_from(ssa, current_block_idx, true_target)? {
                self.emit_phi_stores_for_successor(encoder, ssa, current_block_idx, true_target)?;
            }
            if Some(true_target) != next_block_idx {
                let label = self
                    .block_labels
                    .get(&true_target)
                    .cloned()
                    .unwrap_or_else(|| format!("block_{true_target}"));
                encoder.emit_branch("br", &label)?;
            }
            return Ok(());
        }

        let true_has_phi = self.successor_has_phi_from(ssa, current_block_idx, true_target)?;
        let false_has_phi = self.successor_has_phi_from(ssa, current_block_idx, false_target)?;

        let true_label = self
            .block_labels
            .get(&true_target)
            .cloned()
            .unwrap_or_else(|| format!("block_{true_target}"));
        let false_label = self
            .block_labels
            .get(&false_target)
            .cloned()
            .unwrap_or_else(|| format!("block_{false_target}"));

        // Simple case: no phi stores needed for either target
        if !true_has_phi && !false_has_phi {
            if Some(false_target) == next_block_idx {
                encoder.emit_branch("brtrue", &true_label)?;
            } else if Some(true_target) == next_block_idx {
                encoder.emit_branch("brfalse", &false_label)?;
            } else {
                encoder.emit_branch("brtrue", &true_label)?;
                encoder.emit_branch("br", &false_label)?;
            }
            return Ok(());
        }

        // Generate unique intermediate label for false path (true path is inline)
        let phi_false_label = format!("phi_false_{current_block_idx}_{false_target}");

        // Emit the conditional branch
        // Strategy: brfalse to false handling, then handle true path
        if true_has_phi {
            encoder.emit_branch(
                "brfalse",
                if false_has_phi {
                    &phi_false_label
                } else {
                    &false_label
                },
            )?;

            // True path: emit phi stores then jump
            self.emit_phi_stores_for_successor(encoder, ssa, current_block_idx, true_target)?;
            if Some(true_target) != next_block_idx {
                encoder.emit_branch("br", &true_label)?;
            }
        } else {
            // No phi stores for true - just branch directly
            encoder.emit_branch("brtrue", &true_label)?;
        }

        // False path handling
        if false_has_phi {
            // Define the intermediate label for false path
            if true_has_phi {
                encoder.define_label(&phi_false_label)?;
            }
            // Emit phi stores for false target
            self.emit_phi_stores_for_successor(encoder, ssa, current_block_idx, false_target)?;
            if Some(false_target) != next_block_idx {
                encoder.emit_branch("br", &false_label)?;
            }
        } else if !true_has_phi {
            // Neither has phi, but we need to handle fallthrough
            if Some(false_target) != next_block_idx {
                encoder.emit_branch("br", &false_label)?;
            }
        }

        Ok(())
    }

    /// Emits a comparison branch (beq, blt, etc.) with proper phi store handling.
    #[allow(clippy::too_many_arguments)] // Branch emission requires comparison type, targets, and context
    fn emit_branch_cmp_with_phi_stores(
        &mut self,
        encoder: &mut InstructionEncoder,
        ssa: &SsaFunction,
        current_block_idx: usize,
        cmp: CmpKind,
        unsigned: bool,
        true_target: usize,
        false_target: usize,
        next_block_idx: Option<usize>,
    ) -> Result<()> {
        // Same-target: comparison is irrelevant, discard both operands
        if true_target == false_target {
            encoder.emit_instruction("pop", None)?;
            encoder.emit_instruction("pop", None)?;
            if self.successor_has_phi_from(ssa, current_block_idx, true_target)? {
                self.emit_phi_stores_for_successor(encoder, ssa, current_block_idx, true_target)?;
            }
            if Some(true_target) != next_block_idx {
                let label = self
                    .block_labels
                    .get(&true_target)
                    .cloned()
                    .unwrap_or_else(|| format!("block_{true_target}"));
                encoder.emit_branch("br", &label)?;
            }
            return Ok(());
        }

        let true_has_phi = self.successor_has_phi_from(ssa, current_block_idx, true_target)?;
        let false_has_phi = self.successor_has_phi_from(ssa, current_block_idx, false_target)?;

        let true_label = self
            .block_labels
            .get(&true_target)
            .cloned()
            .unwrap_or_else(|| format!("block_{true_target}"));
        let false_label = self
            .block_labels
            .get(&false_target)
            .cloned()
            .unwrap_or_else(|| format!("block_{false_target}"));

        // Get the comparison mnemonic and its inverse
        let (mnemonic, inverse_mnemonic) = match (cmp, unsigned) {
            (CmpKind::Eq, _) => ("beq", "bne.un"),
            (CmpKind::Ne, _) => ("bne.un", "beq"),
            (CmpKind::Lt, false) => ("blt", "bge"),
            (CmpKind::Lt, true) => ("blt.un", "bge.un"),
            (CmpKind::Le, false) => ("ble", "bgt"),
            (CmpKind::Le, true) => ("ble.un", "bgt.un"),
            (CmpKind::Gt, false) => ("bgt", "ble"),
            (CmpKind::Gt, true) => ("bgt.un", "ble.un"),
            (CmpKind::Ge, false) => ("bge", "blt"),
            (CmpKind::Ge, true) => ("bge.un", "blt.un"),
        };

        // Simple case: no phi stores needed for either target
        if !true_has_phi && !false_has_phi {
            encoder.emit_branch(mnemonic, &true_label)?;
            if Some(false_target) != next_block_idx {
                encoder.emit_branch("br", &false_label)?;
            }
            return Ok(());
        }

        // Generate unique intermediate labels
        let phi_false_label = format!("phi_false_{current_block_idx}_{false_target}");

        if true_has_phi {
            // Use inverse condition to branch to false handling, then handle true inline
            encoder.emit_branch(
                inverse_mnemonic,
                if false_has_phi {
                    &phi_false_label
                } else {
                    &false_label
                },
            )?;

            // True path: emit phi stores then jump
            self.emit_phi_stores_for_successor(encoder, ssa, current_block_idx, true_target)?;
            if Some(true_target) != next_block_idx {
                encoder.emit_branch("br", &true_label)?;
            }
        } else {
            // No phi stores for true - just branch directly
            encoder.emit_branch(mnemonic, &true_label)?;
        }

        // False path handling
        if false_has_phi {
            if true_has_phi {
                encoder.define_label(&phi_false_label)?;
            }
            self.emit_phi_stores_for_successor(encoder, ssa, current_block_idx, false_target)?;
            if Some(false_target) != next_block_idx {
                encoder.emit_branch("br", &false_label)?;
            }
        } else if !true_has_phi && Some(false_target) != next_block_idx {
            encoder.emit_branch("br", &false_label)?;
        }

        Ok(())
    }

    /// Emits a switch instruction with proper phi store handling.
    ///
    /// For each switch target that has phi nodes from the current block,
    /// we create an intermediate block that executes the phi stores and
    /// then jumps to the actual target.
    fn emit_switch_with_phi_stores(
        &mut self,
        encoder: &mut InstructionEncoder,
        ssa: &SsaFunction,
        current_block_idx: usize,
        targets: &[usize],
        default: usize,
        next_block_idx: Option<usize>,
    ) -> Result<()> {
        // Determine which targets need phi stores
        let mut needs_intermediate: Vec<bool> = Vec::with_capacity(targets.len());
        for &target in targets {
            needs_intermediate.push(self.successor_has_phi_from(ssa, current_block_idx, target)?);
        }
        let default_needs_intermediate =
            self.successor_has_phi_from(ssa, current_block_idx, default)?;

        // Build the label list for the switch instruction
        // Use intermediate labels for targets that need phi stores
        let mut switch_labels: Vec<String> = Vec::with_capacity(targets.len());
        for (i, &target) in targets.iter().enumerate() {
            if needs_intermediate.get(i).copied().unwrap_or(false) {
                switch_labels.push(format!("phi_switch_{current_block_idx}_{i}"));
            } else {
                switch_labels.push(
                    self.block_labels
                        .get(&target)
                        .cloned()
                        .unwrap_or_else(|| format!("block_{target}")),
                );
            }
        }

        // Emit the switch instruction
        let label_refs: Vec<&str> = switch_labels.iter().map(String::as_str).collect();
        encoder.emit_switch(&label_refs)?;

        // Emit jump to default (or intermediate for default)
        let default_label = self
            .block_labels
            .get(&default)
            .cloned()
            .unwrap_or_else(|| format!("block_{default}"));

        if default_needs_intermediate {
            let default_intermediate = format!("phi_switch_{current_block_idx}_default");
            if Some(default) != next_block_idx {
                encoder.emit_branch("br", &default_intermediate)?;
            }

            // Emit intermediate blocks for targets that need phi stores
            for (i, &target) in targets.iter().enumerate() {
                if needs_intermediate.get(i).copied().unwrap_or(false) {
                    let intermediate_label = format!("phi_switch_{current_block_idx}_{i}");
                    encoder.define_label(&intermediate_label)?;
                    self.emit_phi_stores_for_successor(encoder, ssa, current_block_idx, target)?;
                    let target_label = self
                        .block_labels
                        .get(&target)
                        .cloned()
                        .unwrap_or_else(|| format!("block_{target}"));
                    encoder.emit_branch("br", &target_label)?;
                }
            }

            // Emit intermediate block for default
            encoder.define_label(&default_intermediate)?;
            self.emit_phi_stores_for_successor(encoder, ssa, current_block_idx, default)?;
            if Some(default) != next_block_idx {
                encoder.emit_branch("br", &default_label)?;
            }
        } else {
            // Default doesn't need phi stores
            if Some(default) != next_block_idx {
                encoder.emit_branch("br", &default_label)?;
            }

            // Emit intermediate blocks for targets that need phi stores
            for (i, &target) in targets.iter().enumerate() {
                if needs_intermediate.get(i).copied().unwrap_or(false) {
                    let intermediate_label = format!("phi_switch_{current_block_idx}_{i}");
                    encoder.define_label(&intermediate_label)?;
                    self.emit_phi_stores_for_successor(encoder, ssa, current_block_idx, target)?;
                    let target_label = self
                        .block_labels
                        .get(&target)
                        .cloned()
                        .unwrap_or_else(|| format!("block_{target}"));
                    encoder.emit_branch("br", &target_label)?;
                }
            }
        }

        Ok(())
    }

    /// Emits phi stores for a successor block.
    ///
    /// This implements phi elimination by converting SSA phi nodes to explicit stores
    /// at the end of predecessor blocks. The key challenge is handling "parallel copy"
    /// semantics correctly - all phi operands must be read BEFORE any are written,
    /// since phi nodes conceptually execute simultaneously.
    ///
    /// For example, consider:
    ///   PHI prev = phi(..., curr)    // prev gets old value of curr
    ///   PHI curr = phi(..., new_val) // curr gets new value
    ///
    /// Naive interleaved load/store would fail if curr is processed first:
    ///   1. Load new_val, store to curr (overwrites old curr!)
    ///   2. Load curr (now wrong!), store to prev
    ///
    /// We solve this by:
    /// 1. Building a dependency graph of the parallel copies
    /// 2. Processing non-cyclic dependencies in topological order
    /// 3. Breaking cycles with a temporary variable
    fn emit_phi_stores_for_successor(
        &mut self,
        encoder: &mut InstructionEncoder,
        ssa: &SsaFunction,
        current_block_idx: usize,
        successor_idx: usize,
    ) -> Result<()> {
        // Get the successor block
        let Some(successor) = ssa.block(successor_idx) else {
            return Ok(());
        };

        // Collect phi copies: (operand_storage, result_storage, operand_var)
        // We track operand_var to use load_var which handles constants correctly.
        //
        // Since Phase 2 pre-allocates all phi results to locals, we can directly
        // build the copies list without a two-phase approach.
        let mut copies: Vec<(VarStorage, VarStorage, SsaVarId)> = Vec::new();

        for phi in successor.phi_nodes() {
            if let Some(operand) = phi.operand_from(current_block_idx) {
                let operand_value = operand.value();
                let phi_result = phi.result();

                // Skip dead phi results (not used by any instructions).
                // These were also skipped during pre-allocation.
                let use_count = self
                    .global_use_counts
                    .get(&phi_result)
                    .copied()
                    .unwrap_or(0);
                if use_count == 0 {
                    continue;
                }

                // Get storage for both operand and result.
                // Phi results are pre-allocated to locals in allocate_storage().
                // Operands may be in args, locals, or need to be loaded (constants).
                let operand_storage = self
                    .var_storage
                    .get(&operand_value)
                    .copied()
                    .unwrap_or(VarStorage::Stack); // Will be loaded via load_var

                let result_storage =
                    self.var_storage.get(&phi_result).copied().ok_or_else(|| {
                        Error::CodegenFailed("Phi result should be pre-allocated".into())
                    })?;

                // Skip if coalesced (both have same storage) AND operand is not on stack.
                // If operand is on stack, we need to emit a store even for same storage.
                let operand_on_stack = self.stack_vars.contains(&operand_value);
                if operand_storage == result_storage && !operand_on_stack {
                    continue;
                }

                // Update type info: use operand's type if more specific than phi's
                if let VarStorage::Local(idx) = result_storage {
                    if let Some(operand_var) = ssa.variable(operand_value) {
                        let operand_type = operand_var.var_type();
                        if !operand_type.is_unknown() && !matches!(operand_type, SsaType::I32) {
                            self.local_types.insert(idx, operand_type.clone());
                        }
                    }
                }

                copies.push((operand_storage, result_storage, operand_value));
            }
        }

        if copies.is_empty() {
            return Ok(());
        }

        // Deduplicate copies with the same source and destination
        let mut seen: HashSet<(VarStorage, VarStorage)> = HashSet::new();
        copies.retain(|(src, dst, _)| seen.insert((*src, *dst)));

        // For correct parallel copy semantics, we must load ALL values before storing ANY.
        // This ensures that reads see the original values, not values modified by other copies.
        //
        // However, we can't just load all values onto the stack because:
        // 1. The stack depth could become large
        // 2. We need to pair loads with the correct stores
        //
        // Solution: Use a simple approach that handles the common cases efficiently:
        // - For non-interfering copies (no copy reads another's destination), do load-store pairs
        // - For interfering copies, use topological order with cycle breaking via temporaries
        //
        // Detect if any copy reads a location that another copy writes
        let has_interference = copies
            .iter()
            .any(|(src, _, _)| copies.iter().any(|(_, dst, _)| src == dst));

        if !has_interference {
            // Simple case: no interference, emit load-store pairs directly
            for (_, result_storage, operand_var) in &copies {
                self.load_var(encoder, ssa, *operand_var)?;
                match result_storage {
                    VarStorage::Local(idx) => {
                        self.used_locals.insert(*idx);
                        emitter::emit_stloc(encoder, *idx)?;
                    }
                    VarStorage::Arg(idx) => emitter::emit_starg(encoder, *idx)?,
                    VarStorage::Stack => {
                        return Err(Error::Deobfuscation(format!(
                            "emit_phi_stores_for_successor: phi result has Stack storage (operand={operand_var:?}) - this indicates a bug in phi pre-allocation"
                        )));
                    }
                }
                // Clear last_load after store to prevent incorrect dup optimization.
                // Without this, a subsequent load from the same local would emit dup
                // instead of ldloc, but the stack is now empty after the store.
                self.last_load = None;
            }
            return Ok(());
        }

        // Complex case: there's interference. Use topological ordering with cycle breaking.
        // Build dependency graph: copy A depends on copy B if A's source = B's destination
        // (i.e., A needs to read before B writes)
        let mut ordered_copies: Vec<(VarStorage, VarStorage, SsaVarId)> = Vec::new();
        let mut pending: Vec<Option<(VarStorage, VarStorage, SsaVarId)>> =
            copies.into_iter().map(Some).collect();
        let mut cycle_copies: Vec<(VarStorage, VarStorage, SsaVarId)> = Vec::new();

        // Iterate until all copies are scheduled
        loop {
            let mut made_progress = false;

            // Find copies whose destination is not read by any other pending copy
            for i in 0..pending.len() {
                let Some((_, dst, _)) = pending.get(i).and_then(|p| p.as_ref()) else {
                    continue;
                };
                let dst = *dst;

                // Check if this destination is read by any other pending copy
                let dst_is_read = pending.iter().enumerate().any(|(j, opt)| {
                    if i == j {
                        return false;
                    }
                    if let Some((src, _, _)) = opt {
                        *src == dst
                    } else {
                        false
                    }
                });

                if !dst_is_read {
                    // Safe to schedule this copy
                    if let Some(copy) = pending.get_mut(i).and_then(Option::take) {
                        ordered_copies.push(copy);
                        made_progress = true;
                    }
                }
            }

            // Count remaining copies
            let remaining: usize = pending.iter().filter(|o| o.is_some()).count();

            if remaining == 0 {
                break;
            }

            if !made_progress {
                // Cycle detected - move all remaining copies to cycle_copies
                for opt in &mut pending {
                    if let Some(copy) = opt.take() {
                        cycle_copies.push(copy);
                    }
                }
                break;
            }
        }

        // Emit non-cyclic copies in order (these are safe as load-store pairs)
        for (_, result_storage, operand_var) in &ordered_copies {
            self.load_var(encoder, ssa, *operand_var)?;
            match result_storage {
                VarStorage::Local(idx) => {
                    self.used_locals.insert(*idx);
                    emitter::emit_stloc(encoder, *idx)?;
                }
                VarStorage::Arg(idx) => emitter::emit_starg(encoder, *idx)?,
                VarStorage::Stack => {
                    return Err(Error::Deobfuscation(format!(
                        "emit_phi_stores_for_successor: phi result has Stack storage (operand={operand_var:?}) - this indicates a bug in phi pre-allocation"
                    )));
                }
            }
            // Clear last_load after store to prevent incorrect dup optimization
            self.last_load = None;
        }

        // Handle cyclic copies using temporaries
        // For a cycle like: A -> B -> C -> A
        // We need to: save A to temp, do B->A, C->B, temp->C
        // Use the temp pool for slot reuse.
        if !cycle_copies.is_empty() {
            // Load all cycle sources first, storing to temporaries
            let mut temps: Vec<(u16, SsaType, VarStorage)> = Vec::new();
            for (_, result_storage, operand_var) in &cycle_copies {
                self.load_var(encoder, ssa, *operand_var)?;

                // Determine the type for this temporary
                let var_type = Self::infer_variable_type(ssa, *operand_var)?;

                // Allocate from pool or fresh
                let temp_idx = self.allocate_temp_local(&var_type);

                self.used_locals.insert(temp_idx);
                emitter::emit_stloc(encoder, temp_idx)?;
                self.last_load = None; // Clear after store
                temps.push((temp_idx, var_type, *result_storage));
            }

            // Now store from temporaries to destinations, then release temps
            for (temp_idx, var_type, result_storage) in temps {
                self.used_locals.insert(temp_idx);
                emitter::emit_ldloc(encoder, temp_idx)?;
                match result_storage {
                    VarStorage::Local(idx) => {
                        self.used_locals.insert(idx);
                        emitter::emit_stloc(encoder, idx)?;
                    }
                    VarStorage::Arg(idx) => emitter::emit_starg(encoder, idx)?,
                    VarStorage::Stack => {
                        return Err(Error::Deobfuscation(
                            "emit_phi_stores_for_successor: phi result has Stack storage in cycle handling - this indicates a bug in phi pre-allocation".to_string()
                        ));
                    }
                }
                self.last_load = None; // Clear after store

                // Release temp back to pool for reuse
                self.release_temp_local(temp_idx, &var_type);
            }
        }

        Ok(())
    }
}
