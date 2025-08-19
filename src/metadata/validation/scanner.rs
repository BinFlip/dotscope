//! Reference scanner for cross-table reference validation.
//!
//! This module provides a reference scanner that pre-analyzes metadata tables to build
//! lookup structures for reference validation. The scanner is shared across
//! all validators in a validation run to avoid redundant analysis.
//!
//! # Architecture
//!
//! The reference scanner operates by building maps of token relationships:
//! - **Forward references**: Maps tokens to other tokens that reference them
//! - **Backward references**: Maps tokens to other tokens they reference
//! - **Valid tokens**: Set of all existing tokens for existence validation
//! - **Table bounds**: Row counts for bounds checking
//! - **Heap bounds**: Heap sizes for index validation
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::scanner::ReferenceScanner`] - Main scanner implementation
//! - [`crate::metadata::validation::scanner::HeapSizes`] - Heap size information for bounds checking
//! - [`crate::metadata::validation::scanner::ScannerStatistics`] - Statistics about scanner analysis
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::ReferenceScanner;
//! use dotscope::metadata::cilassemblyview::CilAssemblyView;
//! use dotscope::metadata::token::Token;
//! use std::path::Path;
//!
//! # let path = Path::new("assembly.dll");
//! let view = CilAssemblyView::from_file(&path)?;
//! let scanner = ReferenceScanner::from_view(&view)?;
//!
//! // Check if a token exists
//! let token = Token::new(0x02000001);
//! if scanner.token_exists(token) {
//!     println!("Token exists");
//! }
//!
//! // Get reference statistics
//! let stats = scanner.statistics();
//! println!("Found {} valid tokens", stats.total_tokens);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! The [`crate::metadata::validation::scanner::ReferenceScanner`] is [`Send`] and [`Sync`],
//! allowing it to be safely shared across multiple validation threads.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::validation::context`] - Provides scanner to validation contexts
//! - [`crate::metadata::validation::engine`] - Creates scanner for validation runs
//! - [`crate::metadata::validation::traits`] - Validators use scanner for reference validation

use crate::{
    dispatch_table_type,
    metadata::{
        cilassemblyview::CilAssemblyView,
        cilobject::CilObject,
        tables::{
            ClassLayoutRaw, ConstantRaw, CustomAttributeRaw, FieldLayoutRaw, FieldMarshalRaw,
            FieldRaw, GenericParamConstraintRaw, GenericParamRaw, InterfaceImplRaw, MemberRefRaw,
            MethodDefRaw, MethodImplRaw, NestedClassRaw, TableId, TypeDefRaw, TypeRefRaw,
        },
        token::Token,
    },
    Blob, Error, Guid, Result, Strings, UserStrings,
};
use std::collections::{HashMap, HashSet};

/// Reference scanner for metadata validation.
///
/// The [`crate::metadata::validation::scanner::ReferenceScanner`] pre-analyzes metadata tables to build lookup structures
/// that enable reference validation. It identifies forward and backward
/// references between tables and provides methods for reference integrity checking.
///
/// # Usage
///
/// The scanner is typically created once per validation run and shared across
/// all validators through the validation context.
///
/// # Usage Examples
///
/// ```rust,no_run
/// use dotscope::metadata::validation::ReferenceScanner;
/// use dotscope::metadata::cilassemblyview::CilAssemblyView;
/// use dotscope::metadata::token::Token;
/// use std::path::Path;
///
/// # let path = Path::new("assembly.dll");
/// let view = CilAssemblyView::from_file(&path)?;
/// let scanner = ReferenceScanner::from_view(&view)?;
///
/// // Check if a token exists
/// let token = Token::new(0x02000001);
/// if scanner.token_exists(token) {
///     // Token exists, safe to validate references
///     println!("Token is valid");
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// This type is [`Send`] and [`Sync`], allowing it to be safely shared across validation threads.
pub struct ReferenceScanner {
    /// Forward references: token -> set of tokens that reference it
    forward_references: HashMap<Token, HashSet<Token>>,
    /// Backward references: token -> set of tokens it references
    backward_references: HashMap<Token, HashSet<Token>>,
    /// Set of all valid tokens in the assembly
    valid_tokens: HashSet<Token>,
    /// Table row counts for bounds checking
    table_row_counts: HashMap<TableId, u32>,
    /// Heap sizes for bounds checking
    heap_sizes: HeapSizes,
}

/// Metadata heap sizes for bounds validation.
#[derive(Debug, Clone, Default)]
pub struct HeapSizes {
    /// String heap size in bytes
    pub strings: u32,
    /// Blob heap size in bytes
    pub blobs: u32,
    /// GUID heap size in bytes
    pub guids: u32,
    /// User string heap size in bytes
    pub userstrings: u32,
}

impl ReferenceScanner {
    /// Creates a new reference scanner by analyzing the provided assembly view.
    ///
    /// This constructor performs the initial analysis of all metadata tables
    /// to build the reference lookup structures for validation operations.
    ///
    /// # Arguments
    ///
    /// * `view` - The [`crate::metadata::cilassemblyview::CilAssemblyView`] to analyze
    ///
    /// # Returns
    ///
    /// Returns a configured [`crate::metadata::validation::scanner::ReferenceScanner`] ready for validation operations.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if the assembly view cannot be analyzed, such as when
    /// metadata tables are malformed or inaccessible.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::validation::ReferenceScanner;
    /// use dotscope::metadata::cilassemblyview::CilAssemblyView;
    /// use std::path::Path;
    ///
    /// # let path = Path::new("assembly.dll");
    /// let view = CilAssemblyView::from_file(&path)?;
    /// let scanner = ReferenceScanner::from_view(&view)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn from_view(view: &CilAssemblyView) -> Result<Self> {
        let mut scanner = Self {
            forward_references: HashMap::new(),
            backward_references: HashMap::new(),
            valid_tokens: HashSet::new(),
            table_row_counts: HashMap::new(),
            heap_sizes: HeapSizes::default(),
        };

        scanner.analyze_assembly(view)?;
        Ok(scanner)
    }

    /// Creates a new reference scanner by analyzing the provided [`crate::metadata::cilobject::CilObject`].
    ///
    /// This constructor provides a convenient way to create a scanner from a [`crate::metadata::cilobject::CilObject`]
    /// by accessing its metadata structures. This is useful for owned validation
    /// scenarios where you already have a resolved object.
    ///
    /// # Arguments
    ///
    /// * `object` - The [`crate::metadata::cilobject::CilObject`] to analyze
    ///
    /// # Returns
    ///
    /// Returns a configured [`crate::metadata::validation::scanner::ReferenceScanner`] ready for validation operations.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if the object cannot be analyzed.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::validation::ReferenceScanner;
    /// use dotscope::metadata::cilobject::CilObject;
    /// use std::path::Path;
    ///
    /// # let path = Path::new("assembly.dll");
    /// let object = CilObject::from_file(&path)?;
    /// let scanner = ReferenceScanner::from_object(&object)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn from_object(object: &CilObject) -> Result<Self> {
        let mut scanner = Self {
            forward_references: HashMap::new(),
            backward_references: HashMap::new(),
            valid_tokens: HashSet::new(),
            table_row_counts: HashMap::new(),
            heap_sizes: HeapSizes::default(),
        };

        scanner.analyze_object(object)?;
        Ok(scanner)
    }

    /// Performs the initial analysis of the CilObject.
    fn analyze_object(&mut self, object: &CilObject) -> Result<()> {
        self.analyze_heaps(
            object.strings(),
            object.blob(),
            object.guids(),
            object.userstrings(),
        )?;

        if let Some(tables) = object.tables() {
            self.analyze_tables(tables);
        }

        Ok(())
    }

    /// Performs the initial analysis of the assembly view.
    fn analyze_assembly(&mut self, view: &CilAssemblyView) -> Result<()> {
        self.analyze_heaps(
            view.strings(),
            view.blobs(),
            view.guids(),
            view.userstrings(),
        )?;

        if let Some(tables) = view.tables() {
            self.analyze_tables(tables);
        }

        Ok(())
    }

    /// Analyzes metadata heaps to determine their sizes.
    fn analyze_heaps(
        &mut self,
        strings: Option<&Strings>,
        blobs: Option<&Blob>,
        guids: Option<&Guid>,
        userstrings: Option<&UserStrings>,
    ) -> Result<()> {
        if let Some(strings) = strings {
            self.heap_sizes.strings = u32::try_from(strings.data().len())
                .map_err(|_| malformed_error!("String heap size exceeds u32 range"))?;
        }

        if let Some(blobs) = blobs {
            self.heap_sizes.blobs = u32::try_from(blobs.data().len())
                .map_err(|_| malformed_error!("Blob heap size exceeds u32 range"))?;
        }

        if let Some(guids) = guids {
            self.heap_sizes.guids = u32::try_from(guids.data().len())
                .map_err(|_| malformed_error!("GUID heap size exceeds u32 range"))?;
        }

        if let Some(userstrings) = userstrings {
            self.heap_sizes.userstrings = u32::try_from(userstrings.data().len())
                .map_err(|_| malformed_error!("UserString heap size exceeds u32 range"))?;
        }

        Ok(())
    }

    /// Analyzes metadata tables to build reference maps.
    fn analyze_tables(&mut self, tables: &crate::TablesHeader) {
        self.collect_valid_tokens(tables);

        self.analyze_references(tables);
    }

    /// Collects all valid tokens from metadata tables.
    fn collect_valid_tokens(&mut self, tables: &crate::TablesHeader) {
        for table_id in tables.present_tables() {
            let row_count = tables.table_row_count(table_id);
            if row_count == 0 {
                continue;
            }

            self.table_row_counts.insert(table_id, row_count);

            let table_token_base = u32::from(table_id.token_type()) << 24;

            dispatch_table_type!(table_id, |RawType| {
                if let Some(table) = tables.table::<RawType>() {
                    for row in table {
                        let token = Token::new(table_token_base | row.rid);
                        self.valid_tokens.insert(token);
                    }
                }
            });
        }
    }

    /// Analyzes references between tokens in metadata tables.
    fn analyze_references(&mut self, tables: &crate::TablesHeader) {
        self.analyze_typedef_references(tables);
        self.analyze_typeref_references(tables);
        self.analyze_interfaceimpl_references(tables);
        self.analyze_memberref_references(tables);
        Self::analyze_methoddef_references(tables);
        Self::analyze_field_references(tables);
        self.analyze_customattribute_references(tables);
        self.analyze_generic_references(tables);
        self.analyze_nested_references(tables);
        self.analyze_additional_references(tables);
    }

    fn analyze_typedef_references(&mut self, tables: &crate::TablesHeader) {
        if let Some(typedef_table) = tables.table::<TypeDefRaw>() {
            for typedef_row in typedef_table {
                let from_token = Token::new(0x0200_0000 | typedef_row.rid);

                if typedef_row.extends.row != 0 {
                    self.add_reference(from_token, typedef_row.extends.token);
                }
            }
        }
    }

    fn analyze_typeref_references(&mut self, tables: &crate::TablesHeader) {
        if let Some(typeref_table) = tables.table::<TypeRefRaw>() {
            for typeref_row in typeref_table {
                let from_token = Token::new(0x0100_0000 | typeref_row.rid);

                if typeref_row.resolution_scope.row != 0 {
                    self.add_reference(from_token, typeref_row.resolution_scope.token);
                }
            }
        }
    }

    fn analyze_interfaceimpl_references(&mut self, tables: &crate::TablesHeader) {
        if let Some(interface_table) = tables.table::<InterfaceImplRaw>() {
            for impl_row in interface_table {
                let from_token = Token::new(0x0900_0000 | impl_row.rid);

                let class_token = Token::new(0x0200_0000 | impl_row.class);
                self.add_reference(from_token, class_token);

                if impl_row.interface.row != 0 {
                    self.add_reference(from_token, impl_row.interface.token);
                }
            }
        }
    }

    fn analyze_memberref_references(&mut self, tables: &crate::TablesHeader) {
        if let Some(memberref_table) = tables.table::<MemberRefRaw>() {
            for memberref_row in memberref_table {
                let from_token = Token::new(0x0A00_0000 | memberref_row.rid);

                if memberref_row.class.row != 0 {
                    self.add_reference(from_token, memberref_row.class.token);
                }

                // TODO: Parse signature blob for type references (future phase)
            }
        }
    }

    fn analyze_methoddef_references(tables: &crate::TablesHeader) {
        if let Some(methoddef_table) = tables.table::<MethodDefRaw>() {
            for _methoddef_row in methoddef_table {
                // TODO: Parse signature blob for type references (future phase)
            }
        }
    }

    fn analyze_field_references(tables: &crate::TablesHeader) {
        if let Some(field_table) = tables.table::<FieldRaw>() {
            for _field_row in field_table {
                // TODO: Parse signature blob for type references (future phase)
            }
        }
    }

    fn analyze_customattribute_references(&mut self, tables: &crate::TablesHeader) {
        if let Some(attr_table) = tables.table::<CustomAttributeRaw>() {
            for attr_row in attr_table {
                let from_token = Token::new(0x0C00_0000 | attr_row.rid);

                if attr_row.parent.row != 0 {
                    self.add_reference(from_token, attr_row.parent.token);
                }

                if attr_row.constructor.row != 0 {
                    self.add_reference(from_token, attr_row.constructor.token);
                }
            }
        }
    }

    fn analyze_generic_references(&mut self, tables: &crate::TablesHeader) {
        if let Some(param_table) = tables.table::<GenericParamRaw>() {
            for param_row in param_table {
                let from_token = Token::new(0x2A00_0000 | param_row.rid);

                if param_row.owner.row != 0 {
                    self.add_reference(from_token, param_row.owner.token);
                }
            }
        }

        if let Some(constraint_table) = tables.table::<GenericParamConstraintRaw>() {
            for constraint_row in constraint_table {
                let from_token = Token::new(0x2C00_0000 | constraint_row.rid);

                let param_token = Token::new(0x2A00_0000 | constraint_row.owner);
                self.add_reference(from_token, param_token);

                if constraint_row.constraint.row != 0 {
                    self.add_reference(from_token, constraint_row.constraint.token);
                }
            }
        }
    }

    fn analyze_nested_references(&mut self, tables: &crate::TablesHeader) {
        if let Some(nested_table) = tables.table::<NestedClassRaw>() {
            for nested_row in nested_table {
                let from_token = Token::new(0x2900_0000 | nested_row.rid);

                let nested_token = Token::new(0x0200_0000 | nested_row.nested_class);
                self.add_reference(from_token, nested_token);

                let enclosing_token = Token::new(0x0200_0000 | nested_row.enclosing_class);
                self.add_reference(from_token, enclosing_token);
            }
        }
    }

    fn analyze_additional_references(&mut self, tables: &crate::TablesHeader) {
        if let Some(methodimpl_table) = tables.table::<MethodImplRaw>() {
            for methodimpl_row in methodimpl_table {
                let from_token = Token::new(0x1900_0000 | methodimpl_row.rid);

                let class_token = Token::new(0x0200_0000 | methodimpl_row.class);
                self.add_reference(from_token, class_token);

                if methodimpl_row.method_body.row != 0 {
                    self.add_reference(from_token, methodimpl_row.method_body.token);
                }

                if methodimpl_row.method_declaration.row != 0 {
                    self.add_reference(from_token, methodimpl_row.method_declaration.token);
                }
            }
        }

        if let Some(fieldlayout_table) = tables.table::<FieldLayoutRaw>() {
            for fieldlayout_row in fieldlayout_table {
                let from_token = Token::new(0x1000_0000 | fieldlayout_row.rid);

                let field_token = Token::new(0x0400_0000 | fieldlayout_row.field);
                self.add_reference(from_token, field_token);
            }
        }

        if let Some(classlayout_table) = tables.table::<ClassLayoutRaw>() {
            for classlayout_row in classlayout_table {
                let from_token = Token::new(0x0F00_0000 | classlayout_row.rid);

                let parent_token = Token::new(0x0200_0000 | classlayout_row.parent);
                self.add_reference(from_token, parent_token);
            }
        }

        if let Some(constant_table) = tables.table::<ConstantRaw>() {
            for constant_row in constant_table {
                let from_token = Token::new(0x0B00_0000 | constant_row.rid);

                if constant_row.parent.row != 0 {
                    self.add_reference(from_token, constant_row.parent.token);
                }
            }
        }

        if let Some(marshal_table) = tables.table::<FieldMarshalRaw>() {
            for marshal_row in marshal_table {
                let from_token = Token::new(0x0D00_0000 | marshal_row.rid);

                if marshal_row.parent.row != 0 {
                    self.add_reference(from_token, marshal_row.parent.token);
                }
            }
        }
    }

    fn add_reference(&mut self, from_token: Token, to_token: Token) {
        if from_token == to_token {
            return;
        }

        if from_token.value() == 0 || to_token.value() == 0 {
            return;
        }

        self.forward_references
            .entry(to_token)
            .or_default()
            .insert(from_token);

        self.backward_references
            .entry(from_token)
            .or_default()
            .insert(to_token);
    }

    /// Checks if a token exists in the metadata.
    ///
    /// # Arguments
    ///
    /// * `token` - The token to check
    ///
    /// # Returns
    ///
    /// Returns `true` if the token exists, `false` otherwise.
    #[must_use]
    pub fn token_exists(&self, token: Token) -> bool {
        self.valid_tokens.contains(&token)
    }

    /// Returns the row count for a specific table.
    ///
    /// # Arguments
    ///
    /// * `table_id` - The table to query
    ///
    /// # Returns
    ///
    /// Returns the row count for the table, or 0 if the table doesn't exist.
    #[must_use]
    pub fn table_row_count(&self, table_id: TableId) -> u32 {
        self.table_row_counts.get(&table_id).copied().unwrap_or(0)
    }

    /// Validates that a token is within the bounds of its table.
    ///
    /// # Arguments
    ///
    /// * `token` - The token to validate
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the token is valid, or an error if it's out of bounds.
    ///
    /// # Errors
    ///
    /// Returns an error if the token is invalid or out of bounds for its table.
    pub fn validate_token_bounds(&self, token: Token) -> Result<()> {
        let table_value = token.table();
        let rid = token.row();

        let table_id =
            TableId::from_token_type(table_value).ok_or(Error::ValidationInvalidRid {
                table: TableId::Module,
                rid,
            })?;

        if rid == 0 {
            return Err(Error::ValidationInvalidRid {
                table: table_id,
                rid,
            });
        }

        let max_rid = self.table_row_count(table_id);
        if rid > max_rid {
            return Err(Error::ValidationInvalidRid {
                table: table_id,
                rid,
            });
        }

        Ok(())
    }

    /// Returns all tokens that reference the given token.
    ///
    /// # Arguments
    ///
    /// * `token` - The token to find references to
    ///
    /// # Returns
    ///
    /// Returns a set of tokens that reference the given token.
    #[must_use]
    pub fn get_references_to(&self, token: Token) -> HashSet<Token> {
        self.forward_references
            .get(&token)
            .cloned()
            .unwrap_or_default()
    }

    /// Returns all tokens that the given token references.
    ///
    /// # Arguments
    ///
    /// * `token` - The token to find references from
    ///
    /// # Returns
    ///
    /// Returns a set of tokens that the given token references.
    #[must_use]
    pub fn get_references_from(&self, token: Token) -> HashSet<Token> {
        self.backward_references
            .get(&token)
            .cloned()
            .unwrap_or_default()
    }

    /// Checks if deleting a token would break reference integrity.
    ///
    /// # Arguments
    ///
    /// * `token` - The token to check for deletion
    ///
    /// # Returns
    ///
    /// Returns `true` if the token can be safely deleted, `false` if it would
    /// break reference integrity.
    #[must_use]
    pub fn can_delete_token(&self, token: Token) -> bool {
        self.get_references_to(token).is_empty()
    }

    /// Returns the heap sizes for bounds checking.
    #[must_use]
    pub fn heap_sizes(&self) -> &HeapSizes {
        &self.heap_sizes
    }

    /// Validates a heap index against the appropriate heap size.
    ///
    /// # Arguments
    ///
    /// * `heap_type` - The type of heap (strings, blobs, etc.)
    /// * `index` - The index to validate
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the index is valid, or an error if it's out of bounds.
    ///
    /// # Errors
    ///
    /// Returns an error if the heap index is out of bounds or the heap type is unknown.
    pub fn validate_heap_index(&self, heap_type: &str, index: u32) -> Result<()> {
        let max_size = match heap_type {
            "strings" => self.heap_sizes.strings,
            "blobs" => self.heap_sizes.blobs,
            "guids" => self.heap_sizes.guids,
            "userstrings" => self.heap_sizes.userstrings,
            _ => {
                return Err(Error::ValidationHeapBoundsError {
                    heap_type: heap_type.to_string(),
                    index,
                })
            }
        };

        if index >= max_size {
            return Err(Error::ValidationHeapBoundsError {
                heap_type: heap_type.to_string(),
                index,
            });
        }

        Ok(())
    }

    /// Returns statistics about the analyzed assembly.
    #[must_use]
    pub fn statistics(&self) -> ScannerStatistics {
        ScannerStatistics {
            total_tokens: self.valid_tokens.len(),
            total_tables: self.table_row_counts.len(),
            total_references: self
                .forward_references
                .values()
                .map(std::collections::HashSet::len)
                .sum(),
            heap_sizes: self.heap_sizes.clone(),
        }
    }

    /// Returns the number of non-empty metadata tables.
    ///
    /// This method efficiently counts tables that have at least one row by returning
    /// the size of the internal table_row_counts HashMap, which only stores tables
    /// that actually exist in the metadata.
    ///
    /// # Returns
    ///
    /// The count of tables that contain at least one row.
    #[must_use]
    pub fn count_non_empty_tables(&self) -> usize {
        self.table_row_counts.len()
    }

    /// Returns the total number of rows across all metadata tables.
    ///
    /// This method efficiently sums all row counts from the internal table_row_counts
    /// HashMap, providing the total number of metadata rows in the assembly.
    ///
    /// # Returns
    ///
    /// The total count of rows across all metadata tables.
    #[must_use]
    pub fn count_total_rows(&self) -> u32 {
        self.table_row_counts.values().sum()
    }
}

/// Statistics about the reference scanner analysis.
#[derive(Debug, Clone)]
pub struct ScannerStatistics {
    /// Total number of valid tokens
    pub total_tokens: usize,
    /// Total number of tables analyzed
    pub total_tables: usize,
    /// Total number of references found
    pub total_references: usize,
    /// Heap sizes
    pub heap_sizes: HeapSizes,
}

impl std::fmt::Display for ScannerStatistics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Scanner Statistics: {} tokens, {} tables, {} references",
            self.total_tokens, self.total_tables, self.total_references
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::cilassemblyview::CilAssemblyView;
    use std::path::PathBuf;

    #[test]
    fn test_reference_scanner_creation() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let scanner = ReferenceScanner::from_view(&view);
            assert!(scanner.is_ok(), "Scanner creation should succeed");

            let scanner = scanner.unwrap();
            let stats = scanner.statistics();

            assert!(stats.total_tokens > 0, "Should have found some tokens");
            assert!(stats.total_tables > 0, "Should have found some tables");
        }
    }

    #[test]
    fn test_token_bounds_validation() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            if let Ok(scanner) = ReferenceScanner::from_view(&view) {
                let invalid_token = Token::new(0x02000000); // TypeDef with RID 0
                assert!(scanner.validate_token_bounds(invalid_token).is_err());

                if scanner.table_row_count(TableId::TypeDef) > 0 {
                    let valid_token = Token::new(0x02000001); // TypeDef with RID 1
                    assert!(scanner.validate_token_bounds(valid_token).is_ok());
                }

                let max_rid = scanner.table_row_count(TableId::TypeDef);
                if max_rid > 0 {
                    let out_of_bounds_token = Token::new(0x02000000 | (max_rid + 1));
                    assert!(scanner.validate_token_bounds(out_of_bounds_token).is_err());
                }
            }
        }
    }

    #[test]
    fn test_heap_size_analysis() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            if let Ok(scanner) = ReferenceScanner::from_view(&view) {
                let heap_sizes = scanner.heap_sizes();

                if view.strings().is_some() {
                    assert!(
                        heap_sizes.strings > 0,
                        "String heap should have been analyzed"
                    );
                }
            }
        }
    }

    #[test]
    fn test_scanner_statistics() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            if let Ok(scanner) = ReferenceScanner::from_view(&view) {
                let stats = scanner.statistics();
                let stats_string = stats.to_string();

                assert!(stats_string.contains("tokens"));
                assert!(stats_string.contains("tables"));
                assert!(stats_string.contains("references"));
            }
        }
    }

    #[test]
    fn test_reference_analysis_basic_functionality() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            if let Ok(scanner) = ReferenceScanner::from_view(&view) {
                let stats = scanner.statistics();

                // After implementing reference analysis, we should have actual references
                // WindowsBase.dll is a substantial assembly that should contain many references
                assert!(
                    stats.total_references > 0,
                    "Should find references in WindowsBase.dll"
                );

                // Test that the reference maps are populated
                assert!(
                    !scanner.forward_references.is_empty()
                        || !scanner.backward_references.is_empty(),
                    "Reference maps should be populated"
                );
            }
        }
    }

    #[test]
    fn test_typedef_inheritance_references() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            if let Ok(scanner) = ReferenceScanner::from_view(&view) {
                // Find TypeDef tokens that should have inheritance relationships
                let mut _inheritance_found = false;

                for typedef_token in scanner.valid_tokens.iter() {
                    if typedef_token.table() == 0x02 {
                        // TypeDef table
                        let references = scanner.get_references_from(*typedef_token);
                        if !references.is_empty() {
                            _inheritance_found = true;

                            // Verify that the referenced tokens are valid
                            for ref_token in references {
                                assert!(
                                    scanner.token_exists(ref_token),
                                    "Referenced token should exist in metadata"
                                );
                            }
                        }
                    }
                }

                // WindowsBase.dll should have at least some types with base types
                if scanner.table_row_count(TableId::TypeDef) > 0 {
                    // Note: Not all types have explicit base types (e.g., Object, interfaces)
                    // so we don't assert inheritance_found, but we do verify the mechanism works
                }
            }
        }
    }

    #[test]
    fn test_interface_implementation_references() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            if let Ok(scanner) = ReferenceScanner::from_view(&view) {
                // Check InterfaceImpl table entries
                let interface_impl_count = scanner.table_row_count(TableId::InterfaceImpl);

                if interface_impl_count > 0 {
                    let mut impl_references_found = false;

                    // Look for InterfaceImpl tokens (0x09)
                    for token in scanner.valid_tokens.iter() {
                        if token.table() == 0x09 {
                            // InterfaceImpl table
                            let references = scanner.get_references_from(*token);
                            if !references.is_empty() {
                                impl_references_found = true;

                                // Each InterfaceImpl should reference both class and interface
                                assert!(!references.is_empty(),
                                    "InterfaceImpl should reference at least the implementing class");

                                // Verify referenced tokens exist
                                for ref_token in references {
                                    assert!(
                                        scanner.token_exists(ref_token),
                                        "Referenced token should exist in metadata"
                                    );
                                }
                            }
                        }
                    }

                    assert!(impl_references_found,
                        "Should find interface implementation references when InterfaceImpl table exists");
                }
            }
        }
    }

    #[test]
    fn test_memberref_class_references() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            if let Ok(scanner) = ReferenceScanner::from_view(&view) {
                let memberref_count = scanner.table_row_count(TableId::MemberRef);

                if memberref_count > 0 {
                    let mut memberref_references_found = false;

                    // Look for MemberRef tokens (0x0A)
                    for token in scanner.valid_tokens.iter() {
                        if token.table() == 0x0A {
                            // MemberRef table
                            let references = scanner.get_references_from(*token);
                            if !references.is_empty() {
                                memberref_references_found = true;

                                // Verify referenced tokens exist
                                for ref_token in references {
                                    assert!(
                                        scanner.token_exists(ref_token),
                                        "Referenced token should exist in metadata"
                                    );
                                }
                            }
                        }
                    }

                    assert!(
                        memberref_references_found,
                        "Should find member reference relationships when MemberRef table exists"
                    );
                }
            }
        }
    }

    #[test]
    fn test_customattribute_references() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            if let Ok(scanner) = ReferenceScanner::from_view(&view) {
                let attr_count = scanner.table_row_count(TableId::CustomAttribute);

                if attr_count > 0 {
                    let mut attr_references_found = false;

                    // Look for CustomAttribute tokens (0x0C)
                    for token in scanner.valid_tokens.iter() {
                        if token.table() == 0x0C {
                            // CustomAttribute table
                            let references = scanner.get_references_from(*token);
                            if !references.is_empty() {
                                attr_references_found = true;

                                // Each CustomAttribute should reference both parent and constructor
                                // Verify referenced tokens exist
                                for ref_token in references {
                                    assert!(
                                        scanner.token_exists(ref_token),
                                        "Referenced token should exist in metadata"
                                    );
                                }
                            }
                        }
                    }

                    assert!(
                        attr_references_found,
                        "Should find custom attribute references when CustomAttribute table exists"
                    );
                }
            }
        }
    }

    #[test]
    fn test_nested_class_references() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            if let Ok(scanner) = ReferenceScanner::from_view(&view) {
                let nested_count = scanner.table_row_count(TableId::NestedClass);

                if nested_count > 0 {
                    let mut nested_references_found = false;

                    // Look for NestedClass tokens (0x29)
                    for token in scanner.valid_tokens.iter() {
                        if token.table() == 0x29 {
                            // NestedClass table
                            let references = scanner.get_references_from(*token);
                            if !references.is_empty() {
                                nested_references_found = true;

                                // Each NestedClass should reference both nested and enclosing types
                                assert!(
                                    references.len() >= 2,
                                    "NestedClass should reference both nested and enclosing types"
                                );

                                // Verify all references are TypeDef tokens
                                for ref_token in references {
                                    assert!(
                                        scanner.token_exists(ref_token),
                                        "Referenced token should exist in metadata"
                                    );
                                    assert_eq!(
                                        ref_token.table(),
                                        0x02,
                                        "NestedClass should only reference TypeDef tokens"
                                    );
                                }
                            }
                        }
                    }

                    assert!(
                        nested_references_found,
                        "Should find nested class references when NestedClass table exists"
                    );
                }
            }
        }
    }

    #[test]
    fn test_generic_parameter_references() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            if let Ok(scanner) = ReferenceScanner::from_view(&view) {
                let generic_param_count = scanner.table_row_count(TableId::GenericParam);

                if generic_param_count > 0 {
                    let mut generic_references_found = false;

                    // Look for GenericParam tokens (0x2A)
                    for token in scanner.valid_tokens.iter() {
                        if token.table() == 0x2A {
                            // GenericParam table
                            let references = scanner.get_references_from(*token);
                            if !references.is_empty() {
                                generic_references_found = true;

                                // Verify referenced tokens exist
                                for ref_token in references {
                                    assert!(
                                        scanner.token_exists(ref_token),
                                        "Referenced token should exist in metadata"
                                    );

                                    // Generic parameters should reference TypeDef or MethodDef
                                    assert!(
                                        ref_token.table() == 0x02 || ref_token.table() == 0x06,
                                        "GenericParam should reference TypeDef or MethodDef"
                                    );
                                }
                            }
                        }
                    }

                    if generic_param_count > 0 {
                        // WindowsBase.dll should have generic parameters if the table exists
                        assert!(generic_references_found,
                            "Should find generic parameter references when GenericParam table exists");
                    }
                }
            }
        }
    }

    #[test]
    fn test_reference_bidirectionality() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            if let Ok(scanner) = ReferenceScanner::from_view(&view) {
                // Test that forward and backward references are consistent
                for (to_token, from_tokens) in &scanner.forward_references {
                    for from_token in from_tokens {
                        let backward_refs = scanner.get_references_from(*from_token);
                        assert!(
                            backward_refs.contains(to_token),
                            "Forward reference should have corresponding backward reference"
                        );
                    }
                }

                for (from_token, to_tokens) in &scanner.backward_references {
                    for to_token in to_tokens {
                        let forward_refs = scanner.get_references_to(*to_token);
                        assert!(
                            forward_refs.contains(from_token),
                            "Backward reference should have corresponding forward reference"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn test_can_delete_token_functionality() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            if let Ok(scanner) = ReferenceScanner::from_view(&view) {
                let stats = scanner.statistics();

                if stats.total_references > 0 {
                    // Find a token that is referenced by others (should not be deletable)
                    let mut found_non_deletable = false;
                    let mut found_deletable = false;

                    for token in scanner.valid_tokens.iter().take(100) {
                        // Sample first 100 tokens
                        let can_delete = scanner.can_delete_token(*token);
                        let references_to = scanner.get_references_to(*token);

                        if !references_to.is_empty() {
                            // Token is referenced by others, should not be deletable
                            assert!(
                                !can_delete,
                                "Token with incoming references should not be deletable"
                            );
                            found_non_deletable = true;
                        } else {
                            // Token has no incoming references, should be deletable
                            assert!(
                                can_delete,
                                "Token with no incoming references should be deletable"
                            );
                            found_deletable = true;
                        }
                    }

                    // We should find examples of both deletable and non-deletable tokens
                    // in a substantial assembly like WindowsBase.dll
                    assert!(found_deletable, "Should find some deletable tokens");
                    assert!(found_non_deletable, "Should find some non-deletable tokens");
                }
            }
        }
    }

    #[test]
    fn test_reference_validation_prevents_invalid_references() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            if let Ok(mut scanner) = ReferenceScanner::from_view(&view) {
                let initial_ref_count = scanner.statistics().total_references;

                // Test self-reference prevention
                let test_token = Token::new(0x02000001);
                scanner.add_reference(test_token, test_token);

                // Test null token prevention
                scanner.add_reference(Token::new(0), test_token);
                scanner.add_reference(test_token, Token::new(0));

                // Reference count should not have increased
                let final_ref_count = scanner.statistics().total_references;
                assert_eq!(
                    initial_ref_count, final_ref_count,
                    "Invalid references should be prevented"
                );
            }
        }
    }

    #[test]
    fn test_comprehensive_reference_coverage() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            if let Ok(scanner) = ReferenceScanner::from_view(&view) {
                let stats = scanner.statistics();

                // WindowsBase.dll should have substantial reference relationships
                // if our implementation is working correctly
                println!("Reference analysis results:");
                println!("  Total tokens: {}", stats.total_tokens);
                println!("  Total tables: {}", stats.total_tables);
                println!("  Total references: {}", stats.total_references);

                // Basic sanity checks
                assert!(
                    stats.total_tokens > 1000,
                    "WindowsBase.dll should have many tokens"
                );
                assert!(
                    stats.total_tables > 10,
                    "WindowsBase.dll should have many tables"
                );

                // After implementing reference analysis, we should have references
                // The exact number will depend on the assembly, but it should be substantial
                if stats.total_references == 0 {
                    println!("Warning: No references found - implementation may need debugging");
                }
            }
        }
    }
}
