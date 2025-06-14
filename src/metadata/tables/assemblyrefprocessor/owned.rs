use std::sync::atomic::Ordering;

use crate::{
    metadata::{tables::AssemblyRefRc, token::Token},
    Result,
};

/// The `AssemblyRefProcessor` table specifies which processors a referenced assembly is targeted for,
/// similar to `AssemblyRefProcessorRaw` but with resolved indexes and fully owned data.
pub struct AssemblyRefProcessor {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 4-byte constant
    pub processor: u32,
    /// an index into the `AssemblyRef` table
    pub assembly_ref: AssemblyRefRc,
}

impl AssemblyRefProcessor {
    /// Apply an `AssemblyRefProcessor` to update the referenced assembly with processor information.
    ///
    /// Since this is the owned structure, the assembly reference is already resolved,
    /// so we can efficiently update the assembly without re-resolving.
    ///
    /// # Errors
    /// Always returns `Ok(())` as this operation doesn't fail.
    pub fn apply(&self) -> Result<()> {
        self.assembly_ref
            .processor
            .store(self.processor, Ordering::Relaxed);
        Ok(())
    }
}
