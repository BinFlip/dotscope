use crate::{
    metadata::{tables::PropertyList, token::Token, typesystem::CilTypeRef},
    Result,
};

/// The resolved `PropertyMap` entry that maps properties to their parent types. Similar to `PropertyMapRaw` but
/// with resolved indexes and owned data.
pub struct PropertyMapEntry {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// The parent type that owns these properties
    pub parent: CilTypeRef,
    /// The list of properties belonging to the parent type
    pub properties: PropertyList,
}

impl PropertyMapEntry {
    /// Apply a `PropertyMapEntry` to update the parent type with its properties.
    ///
    /// Since this is the owned structure, all references are already resolved, so we can
    /// efficiently update the parent type without re-resolving anything.
    ///
    /// # Errors
    /// Returns an error if the parent type reference is invalid or if property assignment fails.
    pub fn apply(&self) -> Result<()> {
        if let Some(parent_type) = self.parent.upgrade() {
            for (_, property) in self.properties.iter() {
                _ = parent_type.properties.push(property.clone());
            }
            Ok(())
        } else {
            Err(malformed_error!(
                "PropertyMapEntry parent type reference is no longer valid"
            ))
        }
    }
}
