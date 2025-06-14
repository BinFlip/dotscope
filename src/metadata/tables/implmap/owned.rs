use std::sync::atomic::Ordering;

use crate::{
    metadata::{method::MethodRc, tables::ModuleRefRc, token::Token},
    Result,
};

/// The `ImplMap` table holds information about platform invoke (P/Invoke) methods. Similar to `ImplMapRaw` but
/// with resolved indexes and owned data
pub struct ImplMap {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 2-byte bitmask of type `PInvokeAttributes`, §II.23.1.8
    pub mapping_flags: u32,
    /// `MemberForwarded` (an index into the Field or `MethodDef` table; more precisely, a `MemberForwarded`
    /// (§II.24.2.6) coded index). However, it only ever indexes the `MethodDef` table, since Field export
    /// is not supported.
    pub member_forwarded: MethodRc,
    /// an index into the String heap
    pub import_name: String,
    /// an index into the `ModuleRef` table
    pub import_scope: ModuleRefRc,
}

impl ImplMap {
    /// Apply an `ImplMap` to update method flags and add import information.
    ///
    /// Since this is the owned structure, all references are already resolved, so we can
    /// efficiently update the method and imports without re-resolving anything.
    ///
    /// # Errors
    /// Returns an error if adding the import fails.
    pub fn apply(&self) -> Result<()> {
        self.member_forwarded
            .flags_pinvoke
            .store(self.mapping_flags, Ordering::Relaxed);

        Ok(())
    }
}
