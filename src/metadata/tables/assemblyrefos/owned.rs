use std::sync::atomic::Ordering;

use crate::{
    metadata::{tables::AssemblyRefRc, token::Token},
    Result,
};

/// The `AssemblyRefOs` table specifies which operating systems a referenced assembly is targeted for,
/// similar to `AssemblyRefOsRaw` but with resolved indexes and fully owned data.
pub struct AssemblyRefOs {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 4-byte constant
    pub os_platform_id: u32,
    /// a 4-byte constant
    pub os_major_version: u32,
    /// a 4-byte constant
    pub os_minor_version: u32,
    /// an index into the `AssemblyRef` table
    pub assembly_ref: AssemblyRefRc,
}

impl AssemblyRefOs {
    /// Apply an `AssemblyRefOs` to update the referenced assembly with OS information.
    ///
    /// Since this is the owned structure, the assembly reference is already resolved,
    /// so we can efficiently update the assembly without re-resolving.
    ///
    /// # Errors
    /// Always returns `Ok(())` as this operation doesn't fail.
    pub fn apply(&self) -> Result<()> {
        self.assembly_ref
            .os_major_version
            .store(self.os_major_version, Ordering::Relaxed);
        self.assembly_ref
            .os_minor_version
            .store(self.os_minor_version, Ordering::Relaxed);
        self.assembly_ref
            .os_platform_id
            .store(self.os_platform_id, Ordering::Relaxed);
        Ok(())
    }
}
