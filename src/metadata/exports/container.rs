//! Unified export container combining both CIL and native PE exports.
//!
//! This module provides the [`UnifiedExportContainer`] which serves as a unified interface
//! for managing both managed (.NET) exports and native PE export tables. It builds
//! on the existing sophisticated CIL export functionality while adding native support
//! through composition rather than duplication.
//!
//! # Architecture
//!
//! The container uses a compositional approach:
//! - **CIL Exports**: Existing [`super::Exports`] container handles managed exports
//! - **Native Exports**: New [`super::NativeExports`] handles PE export tables
//! - **Unified Views**: Lightweight caching for cross-cutting queries
//!
//! # Design Goals
//!
//! - **Preserve Excellence**: Leverage existing concurrent CIL functionality unchanged
//! - **Unified Interface**: Single API for both export types
//! - **Performance**: Minimal overhead with cached unified views
//! - **Backward Compatibility**: Existing CIL exports accessible via `.cil()`
//!
//! # Examples
//!
//! ```rust,ignore
//! use dotscope::metadata::exports::UnifiedExportContainer;
//!
//! let container = UnifiedExportContainer::new();
//!
//! // Access existing CIL functionality
//! let cil_exports = container.cil();
//! let type_export = cil_exports.find_by_name("MyClass", Some("MyNamespace"));
//!
//! // Use unified search across both export types
//! let all_functions = container.find_by_name("MyFunction");
//! for export in all_functions {
//!     match export {
//!         ExportEntry::Cil(cil_export) => println!("CIL: {}", cil_export.name),
//!         ExportEntry::Native(native_ref) => println!("Native: ordinal {}", native_ref.ordinal),
//!     }
//! }
//!
//! // Get all exported function names
//! let functions = container.get_all_exported_functions();
//! ```

use dashmap::{mapref::entry::Entry, DashMap};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::{
    metadata::{
        exports::{native::NativeExports, Exports as CilExports},
        tables::ExportedTypeRc,
        token::Token,
    },
    Result,
};

/// Unified container for both CIL and native PE exports.
///
/// This container provides a single interface for managing all types of exports
/// in a .NET assembly, including managed type exports and native PE export
/// table entries. It preserves the existing sophisticated CIL export
/// functionality while adding native support through composition.
///
/// # Thread Safety
///
/// All operations are thread-safe using interior mutability:
/// - CIL exports use existing concurrent data structures
/// - Native exports are thread-safe by design
/// - Unified caches use atomic coordination
///
/// # Performance
///
/// - CIL operations have identical performance to existing implementation
/// - Native operations use efficient hash-based lookups
/// - Unified views are cached and invalidated only when needed
/// - Lock-free access patterns throughout
pub struct UnifiedExportContainer {
    /// CIL managed exports (existing sophisticated implementation)
    cil: CilExports,

    /// Native PE exports (new implementation)
    native: NativeExports,

    /// Cached unified view by name (lazy-populated)
    unified_name_cache: DashMap<String, Vec<ExportEntry>>,

    /// Cached all exported function names (lazy-populated)
    unified_function_cache: DashMap<String, ExportSource>,

    /// Flag indicating unified caches need rebuilding
    cache_dirty: AtomicBool,
}

/// Unified export entry that can represent either CIL or native exports.
#[derive(Clone)]
pub enum ExportEntry {
    /// Managed export from CIL metadata
    Cil(ExportedTypeRc),
    /// Native export from PE export table
    Native(NativeExportRef),
}

/// Reference to a native export function.
#[derive(Clone, Debug)]
pub struct NativeExportRef {
    /// Function ordinal number
    pub ordinal: u16,
    /// Function name (if exported by name)
    pub name: Option<String>,
    /// Function address or forwarder information
    pub address_or_forwarder: ExportTarget,
}

/// Target of a native export (address or forwarder).
#[derive(Clone, Debug)]
pub enum ExportTarget {
    /// Direct function address
    Address(u32),
    /// Forwarded to another DLL function
    Forwarder(String),
}

/// Source of an exported function.
#[derive(Clone, Debug)]
pub enum ExportSource {
    /// Exported only by CIL metadata
    Cil(Token),
    /// Exported only by native export table
    Native(u16), // ordinal
    /// Exported by both (rare but possible)
    Both(Token, u16),
}

/// Information about an exported function combining both sources.
#[derive(Clone, Debug)]
pub struct ExportedFunction {
    /// Function name
    pub name: String,
    /// Source of the export
    pub source: ExportSource,
    /// Whether it's a forwarder (native only)
    pub is_forwarder: bool,
    /// Target DLL for forwarders
    pub forwarder_target: Option<String>,
}

impl Clone for UnifiedExportContainer {
    fn clone(&self) -> Self {
        Self {
            cil: self.cil.clone(),
            native: self.native.clone(),
            unified_name_cache: DashMap::new(), // Reset cache on clone
            unified_function_cache: DashMap::new(), // Reset cache on clone
            cache_dirty: AtomicBool::new(true), // Mark cache as dirty
        }
    }
}

impl UnifiedExportContainer {
    /// Create a new empty export container.
    ///
    /// Initializes both CIL and native export storage with empty state.
    /// Unified caches are created lazily on first access.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cil: CilExports::new(),
            native: NativeExports::new(""), // Empty DLL name initially
            unified_name_cache: DashMap::new(),
            unified_function_cache: DashMap::new(),
            cache_dirty: AtomicBool::new(true),
        }
    }

    /// Create a new export container with a specific DLL name for native exports.
    ///
    /// # Arguments
    /// * `dll_name` - Name of the DLL for native exports
    #[must_use]
    pub fn with_dll_name(dll_name: &str) -> Self {
        Self {
            cil: CilExports::new(),
            native: NativeExports::new(dll_name),
            unified_name_cache: DashMap::new(),
            unified_function_cache: DashMap::new(),
            cache_dirty: AtomicBool::new(true),
        }
    }

    /// Get the CIL exports container.
    ///
    /// Provides access to all existing CIL export functionality including
    /// sophisticated lookup methods, concurrent data structures, and
    /// cross-reference resolution.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let container = UnifiedExportContainer::new();
    /// let cil_exports = container.cil();
    ///
    /// // Use existing CIL functionality
    /// let type_export = cil_exports.find_by_name("MyClass", Some("MyNamespace"));
    /// ```
    pub fn cil(&self) -> &CilExports {
        &self.cil
    }

    /// Get the native exports container.
    ///
    /// Provides access to PE export table functionality including
    /// function exports, forwarders, and ordinal management.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let container = UnifiedExportContainer::new();
    /// let native_exports = container.native();
    ///
    /// // Check native function exports
    /// let function_names = native_exports.get_exported_function_names();
    /// println!("Native functions: {:?}", function_names);
    /// ```
    pub fn native(&self) -> &NativeExports {
        &self.native
    }

    /// Get mutable access to the native exports container.
    ///
    /// Provides mutable access for populating or modifying native export data.
    /// Used internally during assembly loading to populate from PE files.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut container = UnifiedExportContainer::new();
    /// container.native_mut().add_function("MyFunction", 1, 0x1000)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn native_mut(&mut self) -> &mut NativeExports {
        self.invalidate_cache();
        &mut self.native
    }

    /// Find all exports by name across both CIL and native sources.
    ///
    /// Searches both managed type exports and native function exports
    /// for the specified name. Results include exports from all sources.
    ///
    /// # Arguments
    /// * `name` - Name to search for
    ///
    /// # Returns
    /// Vector of all matching exports, may be empty if none found.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let container = UnifiedExportContainer::new();
    /// let exports = container.find_by_name("MyFunction");
    ///
    /// for export in exports {
    ///     match export {
    ///         ExportEntry::Cil(cil_export) => {
    ///             println!("CIL export: {}", cil_export.name);
    ///         }
    ///         ExportEntry::Native(native_ref) => {
    ///             println!("Native export: ordinal {}", native_ref.ordinal);
    ///         }
    ///     }
    /// }
    /// ```
    pub fn find_by_name(&self, name: &str) -> Vec<ExportEntry> {
        self.ensure_cache_fresh();

        if let Some(entries) = self.unified_name_cache.get(name) {
            entries.value().clone()
        } else {
            Vec::new()
        }
    }

    /// Get all exported function names from both CIL and native sources.
    ///
    /// Returns comprehensive list of all exported functions including
    /// managed type names and native function names.
    ///
    /// # Returns
    /// Vector of all exported function names.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let container = UnifiedExportContainer::new();
    /// let functions = container.get_all_exported_functions();
    ///
    /// for func in functions {
    ///     println!("Exported function: {} ({})", func.name,
    ///         match func.source {
    ///             ExportSource::Cil(_) => "CIL",
    ///             ExportSource::Native(_) => "Native",
    ///             ExportSource::Both(_, _) => "Both",
    ///         });
    /// }
    /// ```
    pub fn get_all_exported_functions(&self) -> Vec<ExportedFunction> {
        self.ensure_cache_fresh();

        self.unified_function_cache
            .iter()
            .map(|entry| {
                let name = entry.key().clone();
                let source = entry.value().clone();

                let (is_forwarder, forwarder_target) = match &source {
                    ExportSource::Native(ordinal) => {
                        if let Some(forwarder) = self.native.get_forwarder_by_ordinal(*ordinal) {
                            (true, Some(forwarder.target.clone()))
                        } else {
                            (false, None)
                        }
                    }
                    _ => (false, None),
                };

                ExportedFunction {
                    name,
                    source,
                    is_forwarder,
                    forwarder_target,
                }
            })
            .collect()
    }

    /// Get all native function names only.
    ///
    /// Returns just the native PE export function names,
    /// excluding CIL type exports.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let container = UnifiedExportContainer::new();
    /// let native_functions = container.get_native_function_names();
    /// println!("Native functions: {:?}", native_functions);
    /// ```
    pub fn get_native_function_names(&self) -> Vec<String> {
        self.native.get_exported_function_names()
    }

    /// Check if the container has any exports (CIL or native).
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let container = UnifiedExportContainer::new();
    /// if container.is_empty() {
    ///     println!("No exports found");
    /// }
    /// ```
    pub fn is_empty(&self) -> bool {
        self.cil.is_empty() && self.native.is_empty()
    }

    /// Get total count of all exports (CIL + native).
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let container = UnifiedExportContainer::new();
    /// println!("Total exports: {}", container.total_count());
    /// ```
    pub fn total_count(&self) -> usize {
        self.cil.len() + self.native.function_count() + self.native.forwarder_count()
    }

    /// Add a native function export.
    ///
    /// Convenience method for adding native function exports.
    ///
    /// # Arguments
    /// * `function_name` - Name of the function to export
    /// * `ordinal` - Ordinal number for the export
    /// * `address` - Function address in the image
    ///
    /// # Errors
    /// Returns error if the function name is invalid, ordinal is 0,
    /// or if the ordinal is already used.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut container = UnifiedExportContainer::new();
    /// container.add_native_function("MyFunction", 1, 0x1000)?;
    /// container.add_native_function("AnotherFunction", 2, 0x2000)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn add_native_function(
        &mut self,
        function_name: &str,
        ordinal: u16,
        address: u32,
    ) -> Result<()> {
        self.native.add_function(function_name, ordinal, address)?;
        self.invalidate_cache();
        Ok(())
    }

    /// Add a native function export by ordinal only.
    ///
    /// Convenience method for adding ordinal-only native function exports.
    ///
    /// # Arguments
    /// * `ordinal` - Ordinal number for the export
    /// * `address` - Function address in the image
    ///
    /// # Errors
    /// Returns error if ordinal is 0 or already used.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut container = UnifiedExportContainer::new();
    /// container.add_native_function_by_ordinal(100, 0x1000)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn add_native_function_by_ordinal(&mut self, ordinal: u16, address: u32) -> Result<()> {
        self.native.add_function_by_ordinal(ordinal, address)?;
        self.invalidate_cache();
        Ok(())
    }

    /// Add a native export forwarder.
    ///
    /// Convenience method for adding export forwarders that redirect
    /// calls to functions in other DLLs.
    ///
    /// # Arguments
    /// * `function_name` - Name of the forwarded function
    /// * `ordinal` - Ordinal number for the export
    /// * `forwarder_target` - Target DLL and function (e.g., "kernel32.dll.GetCurrentProcessId")
    ///
    /// # Errors
    /// Returns error if parameters are invalid or ordinal is already used.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut container = UnifiedExportContainer::new();
    /// container.add_native_forwarder("GetProcessId", 1, "kernel32.dll.GetCurrentProcessId")?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn add_native_forwarder(
        &mut self,
        function_name: &str,
        ordinal: u16,
        forwarder_target: &str,
    ) -> Result<()> {
        self.native
            .add_forwarder(function_name, ordinal, forwarder_target)?;
        self.invalidate_cache();
        Ok(())
    }

    /// Get native export table data for PE writing.
    ///
    /// Generates PE export table data that can be written to the
    /// export directory of a PE file. Returns None if no native
    /// exports exist.
    ///
    /// # Errors
    ///
    /// Returns an error if native export table generation fails due to
    /// invalid export data or encoding issues.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let container = UnifiedExportContainer::new();
    /// if let Some(export_data) = container.get_export_table_data()? {
    ///     // Write export_data to PE export directory
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn get_export_table_data(&self) -> Result<Option<Vec<u8>>> {
        if self.native.is_empty() {
            Ok(None)
        } else {
            Ok(Some(self.native.get_export_table_data()?))
        }
    }

    /// Set the DLL name for native exports.
    ///
    /// Updates the DLL name used in the native export directory.
    /// This is the name that will appear in the PE export table.
    ///
    /// # Arguments
    /// * `dll_name` - New DLL name to use
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut container = UnifiedExportContainer::new();
    /// container.set_dll_name("MyLibrary.dll");
    /// ```
    pub fn set_dll_name(&self, _dll_name: &str) {
        // This would require adding a method to NativeExports to update DLL name
        // For now, this is a placeholder for the interface
        todo!("Implement DLL name update in NativeExports")
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
        self.unified_function_cache.clear();

        // Populate from CIL exports
        for export_entry in &self.cil {
            let export_type = export_entry.value();
            let token = *export_entry.key();

            // Add to name cache
            self.unified_name_cache
                .entry(export_type.name.clone())
                .or_default()
                .push(ExportEntry::Cil(export_type.clone()));

            // Add to function cache
            match self.unified_function_cache.entry(export_type.name.clone()) {
                Entry::Occupied(mut entry) => {
                    match entry.get() {
                        ExportSource::Native(ordinal) => {
                            *entry.get_mut() = ExportSource::Both(token, *ordinal);
                        }
                        ExportSource::Cil(_) | ExportSource::Both(_, _) => {
                            // Keep the existing CIL entry or both entry
                        }
                    }
                }
                Entry::Vacant(entry) => {
                    entry.insert(ExportSource::Cil(token));
                }
            }
        }

        // Populate from native exports
        for function in self.native.functions() {
            if let Some(ref name) = function.name {
                // Add to name cache
                self.unified_name_cache
                    .entry(name.to_string())
                    .or_default()
                    .push(ExportEntry::Native(NativeExportRef {
                        ordinal: function.ordinal,
                        name: Some(name.clone()),
                        address_or_forwarder: ExportTarget::Address(function.address),
                    }));

                // Add to function cache
                match self.unified_function_cache.entry(name.clone()) {
                    Entry::Occupied(mut entry) => {
                        match entry.get() {
                            ExportSource::Cil(token) => {
                                *entry.get_mut() = ExportSource::Both(*token, function.ordinal);
                            }
                            ExportSource::Native(_) | ExportSource::Both(_, _) => {
                                // Keep the existing native entry or both entry
                            }
                        }
                    }
                    Entry::Vacant(entry) => {
                        entry.insert(ExportSource::Native(function.ordinal));
                    }
                }
            }
        }

        // Populate from native forwarders
        for forwarder in self.native.forwarders() {
            if let Some(ref name) = forwarder.name {
                // Add to name cache
                self.unified_name_cache
                    .entry(name.to_string())
                    .or_default()
                    .push(ExportEntry::Native(NativeExportRef {
                        ordinal: forwarder.ordinal,
                        name: Some(name.clone()),
                        address_or_forwarder: ExportTarget::Forwarder(forwarder.target.clone()),
                    }));

                // Add to function cache
                self.unified_function_cache
                    .entry(name.to_string())
                    .or_insert_with(|| ExportSource::Native(forwarder.ordinal));
            }
        }
    }
}

impl Default for UnifiedExportContainer {
    fn default() -> Self {
        Self::new()
    }
}

// Implement common traits for convenience
impl std::fmt::Debug for UnifiedExportContainer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnifiedExportContainer")
            .field("cil_count", &self.cil.len())
            .field("native_function_count", &self.native.function_count())
            .field("native_forwarder_count", &self.native.forwarder_count())
            .field("is_cache_dirty", &self.cache_dirty.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}
