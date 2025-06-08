//! Analysis and representation of exported types in .NET assemblies.
//!
//! This module provides types and logic for tracking all types exported by a .NET assembly,
//! including those made available to other assemblies or COM clients. Used for dependency analysis,
//! interop, and assembly metadata inspection.

use std::sync::Arc;

use crossbeam_skiplist::map::Entry;

use crate::{
    metadata::{
        streams::{ExportedTypeList, ExportedTypeMap, ExportedTypeRc},
        token::Token,
        typesystem::CilTypeReference,
    },
    Result,
};

/// Container for exported types from an assembly.
///
/// This struct provides efficient storage and lookup for all types exported by a .NET assembly.
/// Used for dependency analysis, interop, and metadata inspection.
pub struct Exports {
    data: ExportedTypeMap,
}

impl Exports {
    /// Create a new empty Exports container.
    #[must_use]
    pub fn new() -> Self {
        Exports {
            data: ExportedTypeMap::new(),
        }
    }

    /// Insert a new `ExportedType`.
    ///
    /// # Arguments
    /// * `token`   - The type's token
    /// * `export`  - The type
    ///
    /// # Errors
    /// Currently returns `Ok(())` but signature allows for future error conditions.
    pub fn insert(&self, token: Token, export: ExportedTypeRc) -> Result<()> {
        self.data.insert(token, export);

        Ok(())
    }

    /// Get an exported type by its token.
    ///
    /// # Arguments
    /// * `token` - The token to lookup
    pub fn get(&self, token: &Token) -> Option<Entry<Token, ExportedTypeRc>> {
        self.data.get(token)
    }

    /// Get all exported types.
    pub fn types(&self) -> &ExportedTypeMap {
        &self.data
    }

    /// Get an iterator over all exported types.
    ///
    /// Returns an iterator that yields tuples of (Token, `ExportedTypeRc`) for each exported type.
    pub fn iter(&self) -> crossbeam_skiplist::map::Iter<Token, ExportedTypeRc> {
        self.data.iter()
    }

    /// Find an exported type by its name and optional namespace.
    ///
    /// # Arguments
    /// * `name`        - Name of the exported type
    /// * `namespace`   - Namespace of the exported type
    pub fn find_by_name(&self, name: &str, namespace: Option<&str>) -> Option<ExportedTypeRc> {
        for exported_type in &self.data {
            let exported = exported_type.value();

            if exported.name == name {
                if let Some(ns) = namespace {
                    if let Some(exported_ns) = &exported.namespace {
                        if exported_ns == ns {
                            return Some(exported.clone());
                        }
                    } else if ns.is_empty() {
                        return Some(exported.clone());
                    }
                } else if exported.namespace.is_none() {
                    return Some(exported.clone());
                }
            }
        }

        None
    }

    /// Find exported types by their implementation reference.
    ///
    /// # Arguments
    /// * `reference` - The referencing type to look for
    pub fn find_by_implementation(&self, reference: &CilTypeReference) -> ExportedTypeList {
        let result = Arc::new(boxcar::Vec::new());

        for exported_type in &self.data {
            let borrowed = exported_type.value();

            // Compare implementation references
            match (&borrowed.implementation, reference) {
                (CilTypeReference::File(a), CilTypeReference::File(b)) => {
                    if a.token == b.token {
                        result.push(borrowed.clone());
                    }
                }
                (CilTypeReference::AssemblyRef(a), CilTypeReference::AssemblyRef(b)) => {
                    if a.token == b.token {
                        result.push(borrowed.clone());
                    }
                }
                (CilTypeReference::ExportedType(a), CilTypeReference::ExportedType(b)) => {
                    if a.token == b.token {
                        result.push(borrowed.clone());
                    }
                }
                _ => {}
            }
        }

        result
    }

    /// Return the number of exported types.
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if there are no exported types.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl<'a> IntoIterator for &'a Exports {
    type Item = crossbeam_skiplist::map::Entry<'a, Token, ExportedTypeRc>;
    type IntoIter = crossbeam_skiplist::map::Iter<'a, Token, ExportedTypeRc>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl Default for Exports {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        metadata::{token::Token, typesystem::TypeRegistry},
        test::{create_cil_type, create_exportedtype},
    };

    #[test]
    fn new_exports_is_empty() {
        let exports = Exports::new();
        assert_eq!(exports.len(), 0);
        assert!(exports.is_empty());
    }

    #[test]
    fn find_by_name_works() {
        let exports = Exports::new();

        let type_registry = TypeRegistry::new().unwrap();
        let dummy_type = create_cil_type(Token::new(0x02000001), "TestNamespace", "TestType", None);
        type_registry.insert(dummy_type.clone());

        let exported_type = create_exportedtype(dummy_type);

        // Add the exported type to the exports
        exports
            .data
            .insert(Token::new(0x27000001), exported_type.clone());

        // Test finding by name and namespace
        let found = exports.find_by_name("ExportedType", Some("Test.Namespace"));
        assert!(found.is_some());
        assert_eq!(found.unwrap().token, Token::new(0x27000001));

        // Test not finding with wrong namespace
        let not_found = exports.find_by_name("ExportedType", Some("Wrong.Namespace"));
        assert!(not_found.is_none());

        // Test not finding with wrong name
        let not_found = exports.find_by_name("WrongName", Some("Test.Namespace"));
        assert!(not_found.is_none());
    }

    #[test]
    fn iter_works() {
        let exports = Exports::new();

        let type_registry = TypeRegistry::new().unwrap();
        let dummy_type1 =
            create_cil_type(Token::new(0x02000001), "TestNamespace", "TestType1", None);
        let dummy_type2 =
            create_cil_type(Token::new(0x02000002), "TestNamespace", "TestType2", None);
        type_registry.insert(dummy_type1.clone());
        type_registry.insert(dummy_type2.clone());

        let exported_type1 = create_exportedtype(dummy_type1);
        let exported_type2 = create_exportedtype(dummy_type2);

        // Add the exported types to the exports
        exports.data.insert(Token::new(0x27000001), exported_type1);
        exports.data.insert(Token::new(0x27000002), exported_type2);

        // Test that we can iterate over all exported types
        let mut count = 0;
        let mut tokens = Vec::new();

        for entry in exports.iter() {
            count += 1;
            tokens.push(*entry.key());
        }

        assert_eq!(count, 2);
        assert!(tokens.contains(&Token::new(0x27000001)));
        assert!(tokens.contains(&Token::new(0x27000002)));
    }
}
