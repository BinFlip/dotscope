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
//! let scanner = ReferenceScanner::new(&view)?;
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
    metadata::{
        cilassemblyview::CilAssemblyView, cilobject::CilObject, tables::TableId, token::Token,
    },
    Error, Result,
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
/// let scanner = ReferenceScanner::new(&view)?;
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
    /// let scanner = ReferenceScanner::new(&view)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn new(view: &CilAssemblyView) -> Result<Self> {
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
        // Access the internal assembly view through the public API
        // We need to create this through the tables and streams
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
        // Analyze heap sizes using public API
        if let Some(strings) = object.strings() {
            self.heap_sizes.strings = strings.data().len() as u32;
        }
        if let Some(userstrings) = object.userstrings() {
            self.heap_sizes.userstrings = userstrings.data().len() as u32;
        }
        if let Some(guid) = object.guids() {
            self.heap_sizes.guids = guid.data().len() as u32;
        }
        if let Some(blob) = object.blob() {
            self.heap_sizes.blobs = blob.data().len() as u32;
        }

        // Analyze tables if available
        if let Some(tables) = object.tables() {
            self.analyze_tables(tables)?;
        }

        Ok(())
    }

    /// Performs the initial analysis of the assembly view.
    fn analyze_assembly(&mut self, view: &CilAssemblyView) -> Result<()> {
        // Analyze heap sizes
        self.analyze_heaps(view)?;

        // Analyze tables if available
        if let Some(tables) = view.tables() {
            self.analyze_tables(tables)?;
        }

        Ok(())
    }

    /// Analyzes metadata heaps to determine their sizes.
    fn analyze_heaps(&mut self, view: &CilAssemblyView) -> Result<()> {
        // Analyze string heap
        if let Some(strings) = view.strings() {
            self.heap_sizes.strings = strings.data().len() as u32;
        }

        // Analyze blob heap
        if let Some(blobs) = view.blobs() {
            self.heap_sizes.blobs = blobs.data().len() as u32;
        }

        // Analyze GUID heap
        if let Some(guids) = view.guids() {
            self.heap_sizes.guids = guids.data().len() as u32;
        }

        // Analyze user string heap
        if let Some(userstrings) = view.userstrings() {
            self.heap_sizes.userstrings = userstrings.data().len() as u32;
        }

        Ok(())
    }

    /// Analyzes metadata tables to build reference maps.
    fn analyze_tables(&mut self, tables: &crate::TablesHeader) -> Result<()> {
        // First pass: collect all valid tokens and row counts
        self.collect_valid_tokens(tables)?;

        // Second pass: analyze references between tokens
        self.analyze_references(tables)?;

        Ok(())
    }

    /// Collects all valid tokens from metadata tables.
    fn collect_valid_tokens(&mut self, tables: &crate::TablesHeader) -> Result<()> {
        // ToDo: Improve this - Iterate through all tables and collect valid tokens
        for table_id in [
            TableId::Module,
            TableId::TypeRef,
            TableId::TypeDef,
            TableId::Field,
            TableId::MethodDef,
            TableId::Param,
            TableId::InterfaceImpl,
            TableId::MemberRef,
            TableId::Constant,
            TableId::CustomAttribute,
            TableId::FieldMarshal,
            TableId::DeclSecurity,
            TableId::ClassLayout,
            TableId::FieldLayout,
            TableId::StandAloneSig,
            TableId::EventMap,
            TableId::Event,
            TableId::PropertyMap,
            TableId::Property,
            TableId::MethodSemantics,
            TableId::MethodImpl,
            TableId::ModuleRef,
            TableId::TypeSpec,
            TableId::ImplMap,
            TableId::FieldRVA,
            TableId::Assembly,
            TableId::AssemblyProcessor,
            TableId::AssemblyOS,
            TableId::AssemblyRef,
            TableId::AssemblyRefProcessor,
            TableId::AssemblyRefOS,
            TableId::File,
            TableId::ExportedType,
            TableId::ManifestResource,
            TableId::NestedClass,
            TableId::GenericParam,
            TableId::MethodSpec,
            TableId::GenericParamConstraint,
        ] {
            let row_count = tables.table_row_count(table_id);
            if row_count > 0 {
                self.table_row_counts.insert(table_id, row_count);

                // Add all valid tokens for this table
                // Use TableId's token_type method to construct tokens
                let table_token_base = (table_id.token_type() as u32) << 24;

                for rid in 1..=row_count {
                    let token = Token::new(table_token_base | rid);
                    self.valid_tokens.insert(token);
                }
            }
        }

        Ok(())
    }

    /// Analyzes references between tokens in metadata tables.
    fn analyze_references(&mut self, _tables: &crate::TablesHeader) -> Result<()> {
        // TODO: Implement detailed reference analysis
        // This would involve parsing each table type and extracting token references
        // For now, we provide the basic infrastructure

        // Example pattern for analyzing TypeDef table:
        // if let Some(typedef_table) = tables.table_by_id(TableId::TypeDef) {
        //     for rid in 1..=typedef_table.row_count() {
        //         let token = Token::new(TableId::TypeDef.token_type() | rid);
        //         if let Ok(typedef_row) = typedef_table.row(rid) {
        //             // Analyze extends field (references another type)
        //             let extends_token = typedef_row.extends.resolve();
        //             if extends_token.is_valid() {
        //                 self.add_reference(token, extends_token);
        //             }
        //         }
        //     }
        // }

        Ok(())
    }

    /// Adds a reference relationship between two tokens.
    fn add_reference(&mut self, from_token: Token, to_token: Token) {
        // Add forward reference (to_token is referenced by from_token)
        self.forward_references
            .entry(to_token)
            .or_default()
            .insert(from_token);

        // Add backward reference (from_token references to_token)
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
    pub fn validate_token_bounds(&self, token: Token) -> Result<()> {
        let table_value = token.table();
        let rid = token.row();

        // Convert table value back to TableId
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
    pub fn can_delete_token(&self, token: Token) -> bool {
        // Token can be deleted if nothing references it
        self.get_references_to(token).is_empty()
    }

    /// Returns the heap sizes for bounds checking.
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
    pub fn statistics(&self) -> ScannerStatistics {
        ScannerStatistics {
            total_tokens: self.valid_tokens.len(),
            total_tables: self.table_row_counts.len(),
            total_references: self
                .forward_references
                .values()
                .map(|refs| refs.len())
                .sum(),
            heap_sizes: self.heap_sizes.clone(),
        }
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
            let scanner = ReferenceScanner::new(&view);
            assert!(scanner.is_ok(), "Scanner creation should succeed");

            let scanner = scanner.unwrap();
            let stats = scanner.statistics();

            // Should have analyzed some tokens and tables
            assert!(stats.total_tokens > 0, "Should have found some tokens");
            assert!(stats.total_tables > 0, "Should have found some tables");
        }
    }

    #[test]
    fn test_token_bounds_validation() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            if let Ok(scanner) = ReferenceScanner::new(&view) {
                // Test invalid RID (0)
                let invalid_token = Token::new(0x02000000); // TypeDef with RID 0
                assert!(scanner.validate_token_bounds(invalid_token).is_err());

                // Test valid token bounds (assuming TypeDef table has at least 1 row)
                if scanner.table_row_count(TableId::TypeDef) > 0 {
                    let valid_token = Token::new(0x02000001); // TypeDef with RID 1
                    assert!(scanner.validate_token_bounds(valid_token).is_ok());
                }

                // Test out-of-bounds RID
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
            if let Ok(scanner) = ReferenceScanner::new(&view) {
                let heap_sizes = scanner.heap_sizes();

                // Should have analyzed at least the string heap
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
            if let Ok(scanner) = ReferenceScanner::new(&view) {
                let stats = scanner.statistics();
                let stats_string = stats.to_string();

                assert!(stats_string.contains("tokens"));
                assert!(stats_string.contains("tables"));
                assert!(stats_string.contains("references"));
            }
        }
    }
}
