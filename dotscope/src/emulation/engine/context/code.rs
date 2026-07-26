//! Cached, offset-indexed method bodies for the emulation hot path.
//!
//! The interpreter fetches one instruction per executed step, and branches
//! convert absolute RVAs back to method-relative offsets. Both operations used
//! to re-materialize the entire instruction list for the method and scan it
//! linearly, which made executing a method quadratic in its instruction count.
//!
//! [`MethodCode`] decodes a method body once and stores an offset -> index map
//! alongside it, so both lookups become O(1) and the instruction list is shared
//! by reference instead of cloned.

use rustc_hash::FxHashMap;

use crate::assembly::Instruction;

/// A method's instruction list plus an index for O(1) offset lookup.
///
/// Instances are cached per method token in
/// [`EmulationContext`](crate::emulation::engine::context::EmulationContext) and
/// shared behind an `Arc`. A method's instructions are immutable once decoded
/// (`Method::blocks` is a write-once `OnceLock`), so a cached entry stays valid
/// for the lifetime of the owning assembly.
pub struct MethodCode {
    /// The method's instructions in address order.
    instructions: Vec<Instruction>,

    /// RVA of the first instruction, used to convert RVAs to method offsets.
    base_rva: u64,

    /// Maps a method-relative offset to its index in `instructions`.
    ///
    /// Populated only for offsets that correspond to a real instruction start,
    /// so a lookup miss is a genuine invalid instruction pointer.
    offset_to_index: FxHashMap<u32, u32>,
}

impl MethodCode {
    /// Builds the offset index for a decoded instruction list.
    ///
    /// Returns `None` if the list is empty, since an empty body has no base RVA
    /// and must not be cached (the decoder may populate blocks lazily).
    #[must_use]
    pub fn new(instructions: Vec<Instruction>) -> Option<Self> {
        let base_rva = instructions.first()?.rva;

        let mut offset_to_index = FxHashMap::default();
        offset_to_index.reserve(instructions.len());
        for (index, instr) in instructions.iter().enumerate() {
            // Offsets are method-relative and bounded by the IL body size,
            // which the format caps well below u32::MAX.
            let offset = instr.rva.saturating_sub(base_rva);
            if let (Ok(offset), Ok(index)) = (u32::try_from(offset), u32::try_from(index)) {
                offset_to_index.insert(offset, index);
            }
        }

        Some(MethodCode {
            instructions,
            base_rva,
            offset_to_index,
        })
    }

    /// Returns the RVA of the method's first instruction.
    #[must_use]
    pub fn base_rva(&self) -> u64 {
        self.base_rva
    }

    /// Returns the full instruction list.
    #[must_use]
    pub fn instructions(&self) -> &[Instruction] {
        &self.instructions
    }

    /// Returns the instruction starting at `offset`, or `None` if no
    /// instruction begins there.
    #[must_use]
    pub fn instruction_at(&self, offset: u32) -> Option<&Instruction> {
        let index = *self.offset_to_index.get(&offset)?;
        self.instructions.get(index as usize)
    }

    /// Converts an absolute RVA to a method-relative offset.
    ///
    /// Method-relative offsets are bounded by the IL body size (< `u32::MAX`).
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn rva_to_offset(&self, rva: u64) -> u32 {
        rva.saturating_sub(self.base_rva) as u32
    }
}
