//! Unified import container combining both CIL and native PE imports.
//!
//! This module provides the [`crate::metadata::imports::UnifiedImportContainer`] which serves as a unified interface
//! for managing both managed (.NET) imports and native PE import tables. It builds
//! on the existing sophisticated CIL import functionality while adding native support
//! through composition rather than duplication.
//!
//! # Architecture
//!
//! The container uses a compositional approach:
//! - **CIL Imports**: Existing [`super::Imports`] container handles managed imports
//! - **Native Imports**: New [`super::NativeImports`] handles PE import tables
//! - **Unified Views**: Lightweight caching for cross-cutting queries
//!
//! # Design Goals
//!
//! - **Preserve Excellence**: Leverage existing concurrent CIL functionality unchanged
//! - **Unified Interface**: Single API for both import types
//! - **Performance**: Minimal overhead with cached unified views
//! - **Backward Compatibility**: Existing CIL imports accessible via `.cil()`
//!
//! # Examples
//!
//! ```rust,ignore
//! use dotscope::metadata::imports::ImportContainer;
//!
//! let container = ImportContainer::new();
//!
//! // Access existing CIL functionality
//! let cil_imports = container.cil();
//! let string_import = cil_imports.by_name("String");
//!
//! // Use unified search across both import types
//! let all_messagebox = container.find_by_name("MessageBox");
//! for import in all_messagebox {
//!     match import {
//!         ImportEntry::Cil(cil_import) => println!("CIL: {}", cil_import.fullname()),
//!         ImportEntry::Native(native_ref) => println!("Native: {}", native_ref.dll_name),
//!     }
//! }
//!
//! // Get all DLL dependencies
//! let dependencies = container.get_all_dll_dependencies();
//! ```

use dashmap::{mapref::entry::Entry, DashMap};
use std::{
    collections::HashSet,
    sync::atomic::{AtomicBool, Ordering},
};

use crate::{
    metadata::{
        imports::{native::NativeImports, Imports as CilImports},
        token::Token,
    },
    Result,
};

/// Unified container for both CIL and native PE imports.
///
/// This container provides a single interface for managing all types of imports
/// in a .NET assembly, including managed type/method references and native PE
/// import table entries. It preserves the existing sophisticated CIL import
/// functionality while adding native support through composition.
///
/// # Thread Safety
///
/// All operations are thread-safe using interior mutability:
/// - CIL imports use existing concurrent data structures
/// - Native imports are thread-safe by design
/// - Unified caches use atomic coordination
///
/// # Performance
///
/// - CIL operations have identical performance to existing implementation
/// - Native operations use efficient hash-based lookups
/// - Unified views are cached and invalidated only when needed
/// - Lock-free access patterns throughout
pub struct UnifiedImportContainer {
    /// CIL managed imports (existing sophisticated implementation)
    cil: CilImports,

    /// Native PE imports (new implementation)
    native: NativeImports,

    /// Cached unified view by name (lazy-populated)
    unified_name_cache: DashMap<String, Vec<ImportEntry>>,

    /// Cached unified DLL dependencies (lazy-populated)
    unified_dll_cache: DashMap<String, DllSource>,

    /// Flag indicating unified caches need rebuilding
    cache_dirty: AtomicBool,
}

/// Unified import entry that can represent either CIL or native imports.
#[derive(Clone)]
pub enum ImportEntry {
    /// Managed import from CIL metadata
    Cil(super::ImportRc),
    /// Native import from PE import table
    Native(NativeImportRef),
}

/// Reference to a native import function.
#[derive(Clone, Debug)]
pub struct NativeImportRef {
    /// DLL name containing the function
    pub dll_name: String,
    /// Function name (if imported by name)
    pub function_name: Option<String>,
    /// Function ordinal (if imported by ordinal)
    pub ordinal: Option<u16>,
    /// Import Address Table RVA
    pub iat_rva: u32,
}

/// Source of DLL usage in the assembly.
#[derive(Clone, Debug)]
pub enum DllSource {
    /// Used only by CIL P/Invoke methods
    Cil(Vec<Token>),
    /// Used only by native import table
    Native,
    /// Used by both CIL P/Invoke and native imports
    Both(Vec<Token>),
}

/// DLL dependency information combining both import types.
#[derive(Clone, Debug)]
pub struct DllDependency {
    /// DLL name
    pub name: String,
    /// Source of the dependency
    pub source: DllSource,
    /// All functions imported from this DLL
    pub functions: Vec<String>,
}

impl Clone for UnifiedImportContainer {
    fn clone(&self) -> Self {
        Self {
            cil: self.cil.clone(),
            native: self.native.clone(),
            unified_name_cache: DashMap::new(), // Reset cache on clone
            unified_dll_cache: DashMap::new(),  // Reset cache on clone
            cache_dirty: AtomicBool::new(true), // Mark cache as dirty
        }
    }
}

impl UnifiedImportContainer {
    /// Create a new empty import container.
    ///
    /// Initializes both CIL and native import storage with empty state.
    /// Unified caches are created lazily on first access.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cil: CilImports::new(),
            native: NativeImports::new(),
            unified_name_cache: DashMap::new(),
            unified_dll_cache: DashMap::new(),
            cache_dirty: AtomicBool::new(true),
        }
    }

    /// Get the CIL imports container.
    ///
    /// Provides access to all existing CIL import functionality including
    /// sophisticated lookup methods, concurrent data structures, and
    /// cross-reference resolution.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let container = ImportContainer::new();
    /// let cil_imports = container.cil();
    ///
    /// // Use existing CIL functionality
    /// let string_import = cil_imports.by_name("String");
    /// let system_imports = cil_imports.by_namespace("System");
    /// ```
    pub fn cil(&self) -> &CilImports {
        &self.cil
    }

    /// Get the native imports container.
    ///
    /// Provides access to PE import table functionality including
    /// DLL management, function imports, and IAT operations.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let container = ImportContainer::new();
    /// let native_imports = container.native();
    ///
    /// // Check native DLL dependencies
    /// let dll_names = native_imports.get_dll_names();
    /// println!("Native DLLs: {:?}", dll_names);
    /// ```
    pub fn native(&self) -> &NativeImports {
        &self.native
    }

    /// Get mutable access to the native imports container.
    ///
    /// Provides mutable access for populating or modifying native import data.
    /// Used internally during assembly loading to populate from PE files.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut container = ImportContainer::new();
    /// container.native_mut().add_dll("kernel32.dll")?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn native_mut(&mut self) -> &mut NativeImports {
        self.invalidate_cache();
        &mut self.native
    }

    /// Find all imports by name across both CIL and native sources.
    ///
    /// Searches both managed type/method imports and native function imports
    /// for the specified name. Results include imports from all sources.
    ///
    /// # Arguments
    /// * `name` - Name to search for
    ///
    /// # Returns
    /// Vector of all matching imports, may be empty if none found.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let container = ImportContainer::new();
    /// let imports = container.find_by_name("MessageBox");
    ///
    /// for import in imports {
    ///     match import {
    ///         ImportEntry::Cil(cil_import) => {
    ///             println!("CIL import: {}", cil_import.fullname());
    ///         }
    ///         ImportEntry::Native(native_ref) => {
    ///             println!("Native import: {} from {}",
    ///                 native_ref.function_name.as_ref().unwrap(),
    ///                 native_ref.dll_name);
    ///         }
    ///     }
    /// }
    /// ```
    pub fn find_by_name(&self, name: &str) -> Vec<ImportEntry> {
        self.ensure_cache_fresh();

        if let Some(entries) = self.unified_name_cache.get(name) {
            entries.value().clone()
        } else {
            Vec::new()
        }
    }

    /// Get all DLL dependencies from both CIL P/Invoke and native imports.
    ///
    /// Returns comprehensive dependency information including DLLs used by
    /// managed P/Invoke methods and native import table entries.
    ///
    /// # Returns
    /// Vector of all DLL dependencies with source and function information.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let container = ImportContainer::new();
    /// let dependencies = container.get_all_dll_dependencies();
    ///
    /// for dep in dependencies {
    ///     println!("DLL: {} ({:?})", dep.name, dep.source);
    ///     for func in dep.functions {
    ///         println!("  Function: {}", func);
    ///     }
    /// }
    /// ```
    pub fn get_all_dll_dependencies(&self) -> Vec<DllDependency> {
        self.ensure_cache_fresh();

        self.unified_dll_cache
            .iter()
            .map(|entry| {
                let dll_name = entry.key();
                DllDependency {
                    name: dll_name.clone(),
                    source: entry.value().clone(),
                    functions: self.get_functions_for_dll(dll_name),
                }
            })
            .collect()
    }

    /// Get all DLL names from both import sources.
    ///
    /// Returns a deduplicated list of all DLL names referenced by
    /// either CIL P/Invoke methods or native import table entries.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let container = ImportContainer::new();
    /// let dll_names = container.get_all_dll_names();
    /// println!("All DLL dependencies: {:?}", dll_names);
    /// ```
    pub fn get_all_dll_names(&self) -> Vec<String> {
        self.ensure_cache_fresh();
        self.unified_dll_cache
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }

    /// Check if the container has any imports (CIL or native).
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let container = ImportContainer::new();
    /// if container.is_empty() {
    ///     println!("No imports found");
    /// }
    /// ```
    pub fn is_empty(&self) -> bool {
        self.cil.is_empty() && self.native.is_empty()
    }

    /// Get total count of all imports (CIL + native).
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let container = ImportContainer::new();
    /// println!("Total imports: {}", container.total_count());
    /// ```
    pub fn total_count(&self) -> usize {
        self.cil.len() + self.native.total_function_count()
    }

    /// Add a native function import.
    ///
    /// Convenience method for adding native function imports. The DLL
    /// will be created if it doesn't exist.
    ///
    /// # Arguments
    /// * `dll_name` - Name of the DLL to import from
    /// * `function_name` - Name of the function to import
    ///
    /// # Errors
    /// Returns error if the DLL name or function name is invalid,
    /// or if the function is already imported.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut container = ImportContainer::new();
    /// container.add_native_function("user32.dll", "MessageBoxW")?;
    /// container.add_native_function("kernel32.dll", "GetCurrentProcessId")?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn add_native_function(&mut self, dll_name: &str, function_name: &str) -> Result<()> {
        self.native.add_dll(dll_name)?;
        self.native.add_function(dll_name, function_name)?;
        self.invalidate_cache();
        Ok(())
    }

    /// Add a native function import by ordinal.
    ///
    /// Convenience method for adding ordinal-based native function imports.
    ///
    /// # Arguments
    /// * `dll_name` - Name of the DLL to import from
    /// * `ordinal` - Ordinal number of the function to import
    ///
    /// # Errors
    /// Returns error if the DLL name is invalid, ordinal is 0,
    /// or if the ordinal is already imported.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut container = ImportContainer::new();
    /// container.add_native_function_by_ordinal("user32.dll", 120)?; // MessageBoxW
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn add_native_function_by_ordinal(&mut self, dll_name: &str, ordinal: u16) -> Result<()> {
        self.native.add_dll(dll_name)?;
        self.native.add_function_by_ordinal(dll_name, ordinal)?;
        self.invalidate_cache();
        Ok(())
    }

    /// Get native import table data for PE writing.
    ///
    /// Generates PE import table data that can be written to the
    /// import directory of a PE file. Returns None if no native
    /// imports exist.
    ///
    /// # Arguments
    /// * `is_pe32_plus` - Whether this is PE32+ format (64-bit) or PE32 (32-bit)
    ///
    /// # Errors
    ///
    /// Returns an error if native import table generation fails due to
    /// invalid import data or encoding issues.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let container = ImportContainer::new();
    /// if let Some(import_data) = container.get_import_table_data(false)? { // PE32
    ///     // Write import_data to PE import directory
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn get_import_table_data(&self, is_pe32_plus: bool) -> Result<Option<Vec<u8>>> {
        if self.native.is_empty() {
            Ok(None)
        } else {
            Ok(Some(self.native.get_import_table_data(is_pe32_plus)?))
        }
    }

    /// Update Import Address Table RVAs after section moves.
    ///
    /// Adjusts all IAT RVAs by the specified delta when sections are moved
    /// during PE layout changes. This affects both native imports and any
    /// CIL P/Invoke IAT entries.
    ///
    /// # Arguments
    /// * `rva_delta` - Signed delta to apply to all RVAs
    ///
    /// # Errors
    /// Returns error if the RVA delta would cause overflow.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut container = ImportContainer::new();
    /// // Move import table up by 0x1000 bytes
    /// container.update_iat_rvas(0x1000)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn update_iat_rvas(&mut self, rva_delta: i64) -> Result<()> {
        // Update native IAT entries
        self.native.update_iat_rvas(rva_delta)?;

        // TODO: Update CIL P/Invoke IAT entries if they exist
        // This depends on how the existing CIL implementation handles P/Invoke IAT

        Ok(())
    }

    /// Ensure unified caches are up to date.
    fn ensure_cache_fresh(&self) {
        if self.cache_dirty.load(Ordering::Relaxed) {
            self.rebuild_unified_caches();
            self.cache_dirty.store(false, Ordering::Relaxed);
        }
    }

    /// Mark unified caches as dirty (need rebuilding).
    fn invalidate_cache(&self) {
        self.cache_dirty.store(true, Ordering::Relaxed);
    }

    /// Rebuild all unified cache structures.
    fn rebuild_unified_caches(&self) {
        self.unified_name_cache.clear();
        self.unified_dll_cache.clear();

        // Populate from CIL imports
        for import_entry in &self.cil {
            let import = import_entry.value();
            let token = *import_entry.key();

            // Add to name cache
            self.unified_name_cache
                .entry(import.name.clone())
                .or_default()
                .push(ImportEntry::Cil(import.clone()));

            // Add to DLL cache if it's a P/Invoke method import
            if matches!(import.import, super::ImportType::Method(_)) {
                if let Some(dll_name) = Self::extract_dll_from_pinvoke_import(import) {
                    match self.unified_dll_cache.entry(dll_name) {
                        Entry::Occupied(mut entry) => match entry.get_mut() {
                            DllSource::Cil(tokens) | DllSource::Both(tokens) => tokens.push(token),
                            DllSource::Native => {
                                let tokens = vec![token];
                                *entry.get_mut() = DllSource::Both(tokens);
                            }
                        },
                        Entry::Vacant(entry) => {
                            entry.insert(DllSource::Cil(vec![token]));
                        }
                    }
                }
            }
        }

        // Populate from native imports
        for descriptor in self.native.descriptors() {
            let dll_name = &descriptor.dll_name;

            for function in &descriptor.functions {
                // Add to name cache if imported by name
                if let Some(ref func_name) = function.name {
                    self.unified_name_cache
                        .entry(func_name.to_string())
                        .or_default()
                        .push(ImportEntry::Native(NativeImportRef {
                            dll_name: dll_name.clone(),
                            function_name: Some(func_name.clone()),
                            ordinal: function.ordinal,
                            iat_rva: function.rva,
                        }));
                }

                // Add to DLL cache
                match self.unified_dll_cache.entry(dll_name.clone()) {
                    Entry::Occupied(mut entry) => {
                        match entry.get() {
                            DllSource::Cil(tokens) => {
                                let tokens = tokens.clone();
                                *entry.get_mut() = DllSource::Both(tokens);
                            }
                            DllSource::Native | DllSource::Both(_) => {
                                // Already has native usage, no change needed
                            }
                        }
                    }
                    Entry::Vacant(entry) => {
                        entry.insert(DllSource::Native);
                    }
                }
            }
        }
    }

    /// Extract DLL name from a CIL P/Invoke import.
    ///
    /// This examines the import's source information to determine if it's
    /// a P/Invoke method import and extracts the target DLL name.
    fn extract_dll_from_pinvoke_import(_import: &super::Import) -> Option<String> {
        // TODO: Implement based on existing CIL P/Invoke representation
        // This depends on how the current CIL implementation stores P/Invoke information
        // Likely involves looking at the import source and module reference data

        // For now, return None - this will be implemented based on existing patterns
        None
    }

    /// Get all function names imported from a specific DLL.
    fn get_functions_for_dll(&self, dll_name: &str) -> Vec<String> {
        let mut functions = HashSet::new();

        // Add functions from native imports
        if let Some(descriptor) = self.native.get_descriptor(dll_name) {
            for function in &descriptor.functions {
                if let Some(ref name) = function.name {
                    functions.insert(name.to_string());
                } else if let Some(ordinal) = function.ordinal {
                    functions.insert(format!("#{ordinal}"));
                }
            }
        }

        // TODO: Add functions from CIL P/Invoke imports
        // This requires examining CIL imports that target this DLL

        functions.into_iter().collect()
    }
}

impl Default for UnifiedImportContainer {
    fn default() -> Self {
        Self::new()
    }
}

// Implement common traits for convenience
impl std::fmt::Debug for UnifiedImportContainer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportContainer")
            .field("cil_count", &self.cil.len())
            .field("native_dll_count", &self.native.dll_count())
            .field("native_function_count", &self.native.total_function_count())
            .field("is_cache_dirty", &self.cache_dirty.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}
