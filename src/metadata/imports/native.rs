//! Native PE import table support for .NET assemblies.
//!
//! This module provides comprehensive functionality for parsing, analyzing, and generating
//! native PE import tables. It enables dotscope to handle mixed-mode assemblies that contain
//! both managed (.NET) code and native import dependencies from Windows DLLs.
//!
//! # Architecture
//!
//! The native import system implements the PE/COFF import table format with support for:
//!
//! - **Import Descriptors**: Per-DLL import information with lookup table references
//! - **Import Address Table (IAT)**: Runtime-patchable function address storage
//! - **Import Lookup Table (ILT)**: Template for loader processing
//! - **Name Tables**: Function name and hint information for symbol resolution
//!
//! # Key Components
//!
//! - [`NativeImports`] - Main container for PE import table data
//! - [`ImportDescriptor`] - Per-DLL import descriptor with function lists
//! - [`Import`] - Individual function import with name/ordinal information
//! - [`ImportAddressEntry`] - IAT entry with RVA and patching information
//!
//! # Import Table Structure
//!
//! The PE import table follows this layout:
//! ```text
//! Import Directory Table
//! ├── Import Descriptor 1 (DLL A)
//! │   ├── Original First Thunk (ILT RVA)
//! │   ├── First Thunk (IAT RVA)
//! │   └── DLL Name RVA
//! ├── Import Descriptor 2 (DLL B)
//! └── Null Terminator
//!
//! Import Lookup Table (ILT)
//! ├── Function 1 Name RVA/Ordinal
//! ├── Function 2 Name RVA/Ordinal
//! └── Null Terminator
//!
//! Import Address Table (IAT)
//! ├── Function 1 Address (patched by loader)
//! ├── Function 2 Address (patched by loader)
//! └── Null Terminator
//!
//! Name Table
//! ├── Function 1: Hint + Name + Null
//! ├── Function 2: Hint + Name + Null
//! └── DLL Names + Null terminators
//! ```
//!
//! # Usage Examples
//!
//! ## Parse Existing Import Table
//!
//! ```rust,ignore
//! use dotscope::metadata::imports::native::NativeImports;
//!
//! let pe_data = std::fs::read("application.exe")?;
//! let native_imports = NativeImports::parse_from_pe(&pe_data)?;
//!
//! // Analyze DLL dependencies
//! for descriptor in native_imports.descriptors() {
//!     println!("DLL: {}", descriptor.dll_name);
//!     for function in &descriptor.functions {
//!         match &function.name {
//!             Some(name) => println!("  Function: {}", name),
//!             None => println!("  Ordinal: {}", function.ordinal.unwrap()),
//!         }
//!     }
//! }
//! ```
//!
//! ## Create Import Table
//!
//! ```rust,ignore
//! use dotscope::metadata::imports::native::NativeImports;
//!
//! let mut imports = NativeImports::new();
//!
//! // Add DLL and functions
//! imports.add_dll("kernel32.dll")?;
//! imports.add_function("kernel32.dll", "GetCurrentProcessId")?;
//! imports.add_function("kernel32.dll", "ExitProcess")?;
//!
//! imports.add_dll("user32.dll")?;
//! imports.add_function_by_ordinal("user32.dll", 120)?; // MessageBoxW
//!
//! // Generate import table data
//! let import_data = imports.get_import_table_data();
//! ```
//!
//! # Thread Safety
//!
//! All operations on [`NativeImports`] are thread-safe when accessed through shared references.
//! Mutable operations require exclusive access but can be performed concurrently with
//! immutable operations on different instances.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::imports::UnifiedImportContainer`] - Unified import container combining CIL and native
//! - [`crate::cilassembly::CilAssembly`] - PE writing pipeline for import table generation
//! - [`goblin`] - PE parsing library for import directory analysis

use std::collections::HashMap;

use crate::{
    file::pe::Import,
    utils::{write_le_at, write_string_at},
    Error, Result,
};

/// Container for native PE import table data.
///
/// Manages import descriptors, Import Address Table (IAT) entries, and associated
/// metadata for native DLL dependencies. Provides functionality for parsing existing
/// import tables from PE files and generating new import table data.
///
/// # Storage Strategy
/// - **Import Descriptors**: Per-DLL import information with function lists
/// - **IAT Management**: Address tracking for loader patching
/// - **Name Resolution**: Function name and ordinal mapping
/// - **RVA Tracking**: Relative Virtual Address management for relocations
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::metadata::imports::native::NativeImports;
///
/// let mut imports = NativeImports::new();
///
/// // Add a DLL dependency
/// imports.add_dll("kernel32.dll")?;
/// imports.add_function("kernel32.dll", "GetCurrentProcessId")?;
///
/// // Generate import table
/// let table_data = imports.get_import_table_data();
/// println!("Import table size: {} bytes", table_data.len());
/// # Ok::<(), dotscope::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct NativeImports {
    /// Import descriptors indexed by DLL name for fast lookup
    descriptors: HashMap<String, ImportDescriptor>,

    /// Import Address Table entries indexed by RVA
    iat_entries: HashMap<u32, ImportAddressEntry>,

    /// Next available RVA for IAT allocation
    next_iat_rva: u32,

    /// Base RVA for import table structures
    import_table_base_rva: u32,
}

/// Import descriptor for a single DLL.
///
/// Contains all import information for functions from a specific DLL, including
/// Import Lookup Table (ILT) and Import Address Table (IAT) references.
///
/// # PE Format Mapping
/// This structure directly corresponds to the PE IMAGE_IMPORT_DESCRIPTOR:
/// - `original_first_thunk`: RVA of Import Lookup Table (ILT)
/// - `first_thunk`: RVA of Import Address Table (IAT)
/// - `dll_name`: Name of the DLL containing the imported functions
#[derive(Debug, Clone)]
pub struct ImportDescriptor {
    /// Name of the DLL (e.g., "kernel32.dll")
    pub dll_name: String,

    /// RVA of Import Lookup Table (ILT) - template for IAT
    pub original_first_thunk: u32,

    /// RVA of Import Address Table (IAT) - patched by loader
    pub first_thunk: u32,

    /// Functions imported from this DLL  
    pub functions: Vec<Import>,

    /// Timestamp for bound imports (usually 0)
    pub timestamp: u32,

    /// Forwarder chain for bound imports (usually 0)
    pub forwarder_chain: u32,
}

/// Entry in the Import Address Table (IAT).
///
/// Represents a single IAT slot that gets patched by the Windows loader with
/// the actual function address at runtime. Essential for RVA tracking and
/// relocation processing.
#[derive(Debug, Clone)]
pub struct ImportAddressEntry {
    /// RVA of this IAT entry
    pub rva: u32,

    /// DLL containing the imported function
    pub dll_name: String,

    /// Function name or ordinal identifier
    pub function_identifier: String,

    /// Original ILT value before loader patching
    pub original_value: u64,
}

impl NativeImports {
    /// Create a new empty native imports container.
    ///
    /// Initializes an empty container ready for import descriptor creation.
    /// The container starts with default RVA allocation starting at 0x1000.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::imports::NativeImports;
    ///
    /// let imports = NativeImports::new();
    /// assert!(imports.is_empty());
    /// assert_eq!(imports.dll_count(), 0);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            descriptors: HashMap::new(),
            iat_entries: HashMap::new(),
            next_iat_rva: 0x1000,          // Default IAT base address
            import_table_base_rva: 0x2000, // Default import table base
        }
    }

    /// Creates native imports directly from PE import data.
    ///
    /// # Arguments
    /// * `pe_imports` - Slice of PE import entries to process
    ///
    /// # Returns
    /// Returns a configured NativeImports instance with all import descriptors,
    /// IAT entries, and internal structures properly initialized.
    ///
    /// # Errors
    /// Returns error if:
    /// - Memory allocation fails during structure creation
    /// - Import data contains invalid or inconsistent information
    ///
    /// # Examples
    /// ```rust,ignore
    /// use dotscope::metadata::imports::NativeImports;
    /// use dotscope::file::pe::Import;
    ///
    /// let pe_imports = vec![
    ///     Import {
    ///         dll: "kernel32.dll".to_string(),
    ///         name: "GetCurrentProcessId".to_string(),
    ///         ordinal: 0,
    ///         rva: 0x2000,
    ///     },
    /// ];
    ///
    /// let native_imports = NativeImports::from_pe_imports(&pe_imports)?;
    /// assert_eq!(native_imports.dll_count(), 1);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn from_pe_imports(pe_imports: &[Import]) -> Result<Self> {
        let mut scanner = Self::new();

        let mut imports_by_dll: HashMap<&str, Vec<&Import>> = HashMap::new();
        for import in pe_imports {
            imports_by_dll.entry(&import.dll).or_default().push(import);
        }

        for (dll_name, dll_imports) in imports_by_dll {
            let mut descriptor = ImportDescriptor {
                dll_name: dll_name.to_owned(),
                original_first_thunk: 0,
                first_thunk: 0,
                functions: Vec::with_capacity(dll_imports.len()),
                timestamp: 0,
                forwarder_chain: 0,
            };

            for pe_import in dll_imports {
                scanner.iat_entries.insert(
                    pe_import.rva,
                    ImportAddressEntry {
                        rva: pe_import.rva,
                        dll_name: dll_name.to_owned(),
                        function_identifier: if let Some(ref name) = pe_import.name {
                            if name.is_empty() {
                                if let Some(ord) = pe_import.ordinal {
                                    format!("#{}", ord)
                                } else {
                                    "unknown".to_string()
                                }
                            } else {
                                name.clone()
                            }
                        } else if let Some(ord) = pe_import.ordinal {
                            format!("#{}", ord)
                        } else {
                            "unknown".to_string()
                        },
                        original_value: 0, // Not available from current PE Import
                    },
                );

                descriptor.functions.push((*pe_import).clone());
            }

            scanner.descriptors.insert(dll_name.to_owned(), descriptor);
        }

        Ok(scanner)
    }

    /// Add a DLL to the import table.
    ///
    /// Creates a new import descriptor for the specified DLL if it doesn't already exist.
    /// Multiple calls with the same DLL name will reuse the existing descriptor.
    ///
    /// # Arguments
    /// * `dll_name` - Name of the DLL (e.g., "kernel32.dll", "user32.dll")
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::imports::NativeImports;
    ///
    /// let mut imports = NativeImports::new();
    /// imports.add_dll("kernel32.dll")?;
    /// imports.add_dll("user32.dll")?;
    ///
    /// assert_eq!(imports.dll_count(), 2);
    /// assert!(imports.has_dll("kernel32.dll"));
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the DLL name is empty or contains invalid characters.
    pub fn add_dll(&mut self, dll_name: &str) -> Result<()> {
        if dll_name.is_empty() {
            return Err(Error::Error("DLL name cannot be empty".to_string()));
        }

        if !self.descriptors.contains_key(dll_name) {
            let descriptor = ImportDescriptor {
                dll_name: dll_name.to_owned(),
                original_first_thunk: 0, // Will be set during table generation
                first_thunk: 0,          // Will be set during table generation
                functions: Vec::new(),
                timestamp: 0,
                forwarder_chain: 0,
            };

            self.descriptors.insert(dll_name.to_owned(), descriptor);
        }

        Ok(())
    }

    /// Add a function import from a specific DLL.
    ///
    /// Adds a named function import to the specified DLL's import descriptor.
    /// The DLL must be added first using [`add_dll`](Self::add_dll).
    ///
    /// # Arguments
    /// * `dll_name` - Name of the DLL containing the function
    /// * `function_name` - Name of the function to import
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::imports::NativeImports;
    ///
    /// let mut imports = NativeImports::new();
    /// imports.add_dll("kernel32.dll")?;
    /// imports.add_function("kernel32.dll", "GetCurrentProcessId")?;
    /// imports.add_function("kernel32.dll", "ExitProcess")?;
    ///
    /// let descriptor = imports.get_descriptor("kernel32.dll").unwrap();
    /// assert_eq!(descriptor.functions.len(), 2);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The DLL has not been added to the import table
    /// - The function name is empty
    /// - The function is already imported from this DLL
    ///
    /// # Panics
    ///
    /// Panics if the DLL has not been added to the import table first.
    /// Use [`Self::add_dll`] before calling this method.
    pub fn add_function(&mut self, dll_name: &str, function_name: &str) -> Result<()> {
        if function_name.is_empty() {
            return Err(Error::Error("Function name cannot be empty".to_string()));
        }

        if let Some(descriptor) = self.descriptors.get(dll_name) {
            if descriptor
                .functions
                .iter()
                .any(|f| f.name.as_deref() == Some(function_name))
            {
                return Err(Error::Error(format!(
                    "Function '{function_name}' already imported from '{dll_name}'"
                )));
            }
        } else {
            return Err(Error::Error(format!(
                "DLL '{dll_name}' not found in import table"
            )));
        }

        let iat_rva = self.allocate_iat_rva();
        let descriptor = self.descriptors.get_mut(dll_name).unwrap();

        let function = Import {
            dll: dll_name.to_owned(),
            name: Some(function_name.to_owned()),
            ordinal: None,
            rva: iat_rva,
            hint: 0,
            ilt_value: 0,
        };

        let iat_entry = ImportAddressEntry {
            rva: iat_rva,
            dll_name: dll_name.to_owned(),
            function_identifier: function_name.to_owned(),
            original_value: 0,
        };

        descriptor.functions.push(function);
        self.iat_entries.insert(iat_rva, iat_entry);

        Ok(())
    }

    /// Add an ordinal-based function import.
    ///
    /// Adds a function import that uses ordinal-based lookup instead of name-based.
    /// This can be more efficient but is less portable across DLL versions.
    ///
    /// # Arguments
    /// * `dll_name` - Name of the DLL containing the function
    /// * `ordinal` - Ordinal number of the function in the DLL's export table
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::imports::NativeImports;
    ///
    /// let mut imports = NativeImports::new();
    /// imports.add_dll("user32.dll")?;
    /// imports.add_function_by_ordinal("user32.dll", 120)?; // MessageBoxW
    ///
    /// let descriptor = imports.get_descriptor("user32.dll").unwrap();
    /// assert_eq!(descriptor.functions[0].ordinal, Some(120));
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The DLL has not been added to the import table
    /// - The ordinal is 0 (invalid)
    /// - A function with the same ordinal is already imported
    ///
    /// # Panics
    ///
    /// Panics if the DLL has not been added to the import table first.
    /// Use [`Self::add_dll`] before calling this method.
    pub fn add_function_by_ordinal(&mut self, dll_name: &str, ordinal: u16) -> Result<()> {
        if ordinal == 0 {
            return Err(Error::Error("Ordinal cannot be 0".to_string()));
        }

        if let Some(descriptor) = self.descriptors.get(dll_name) {
            if descriptor
                .functions
                .iter()
                .any(|f| f.ordinal == Some(ordinal))
            {
                return Err(Error::Error(format!(
                    "Ordinal {ordinal} already imported from '{dll_name}'"
                )));
            }
        } else {
            return Err(Error::Error(format!(
                "DLL '{dll_name}' not found in import table"
            )));
        }

        let iat_rva = self.allocate_iat_rva();
        let descriptor = self.descriptors.get_mut(dll_name).unwrap();

        let function = Import {
            dll: dll_name.to_owned(),
            name: None,
            ordinal: Some(ordinal),
            rva: iat_rva,
            hint: 0,
            ilt_value: 0x8000_0000_0000_0000u64 | u64::from(ordinal),
        };

        let iat_entry = ImportAddressEntry {
            rva: iat_rva,
            dll_name: dll_name.to_owned(),
            function_identifier: format!("#{ordinal}"),
            original_value: function.ilt_value,
        };

        descriptor.functions.push(function);
        self.iat_entries.insert(iat_rva, iat_entry);

        Ok(())
    }

    /// Get an import descriptor by DLL name.
    ///
    /// Returns a reference to the import descriptor for the specified DLL,
    /// or `None` if the DLL is not in the import table.
    ///
    /// # Arguments
    /// * `dll_name` - Name of the DLL to find
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::imports::NativeImports;
    ///
    /// let mut imports = NativeImports::new();
    /// imports.add_dll("kernel32.dll")?;
    ///
    /// let descriptor = imports.get_descriptor("kernel32.dll");
    /// assert!(descriptor.is_some());
    /// assert_eq!(descriptor.unwrap().dll_name, "kernel32.dll");
    ///
    /// let missing = imports.get_descriptor("missing.dll");
    /// assert!(missing.is_none());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn get_descriptor(&self, dll_name: &str) -> Option<&ImportDescriptor> {
        self.descriptors.get(dll_name)
    }

    /// Get all import descriptors.
    ///
    /// Returns an iterator over all import descriptors in the container.
    /// The order is not guaranteed to be consistent across calls.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::imports::NativeImports;
    ///
    /// let mut imports = NativeImports::new();
    /// imports.add_dll("kernel32.dll")?;
    /// imports.add_dll("user32.dll")?;
    ///
    /// let dll_names: Vec<&str> = imports.descriptors()
    ///     .map(|desc| desc.dll_name.as_str())
    ///     .collect();
    ///
    /// assert_eq!(dll_names.len(), 2);
    /// assert!(dll_names.contains(&"kernel32.dll"));
    /// assert!(dll_names.contains(&"user32.dll"));
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn descriptors(&self) -> impl Iterator<Item = &ImportDescriptor> {
        self.descriptors.values()
    }

    /// Check if a DLL is in the import table.
    ///
    /// Returns `true` if the specified DLL has been added to the import table.
    ///
    /// # Arguments
    /// * `dll_name` - Name of the DLL to check
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::imports::NativeImports;
    ///
    /// let mut imports = NativeImports::new();
    /// imports.add_dll("kernel32.dll")?;
    ///
    /// assert!(imports.has_dll("kernel32.dll"));
    /// assert!(!imports.has_dll("missing.dll"));
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn has_dll(&self, dll_name: &str) -> bool {
        self.descriptors.contains_key(dll_name)
    }

    /// Get the number of DLLs in the import table.
    ///
    /// Returns the count of unique DLLs that have import descriptors.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::imports::NativeImports;
    ///
    /// let imports = NativeImports::new();
    /// assert_eq!(imports.dll_count(), 0);
    /// ```
    #[must_use]
    pub fn dll_count(&self) -> usize {
        self.descriptors.len()
    }

    /// Get the total count of all imported functions across all DLLs.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let imports = NativeImports::new();
    /// println!("Total imported functions: {}", imports.total_function_count());
    /// ```
    #[must_use]
    pub fn total_function_count(&self) -> usize {
        self.descriptors
            .values()
            .map(|descriptor| descriptor.functions.len())
            .sum()
    }

    /// Check if the import table is empty.
    ///
    /// Returns `true` if no DLLs have been added to the import table.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::imports::NativeImports;
    ///
    /// let imports = NativeImports::new();
    /// assert!(imports.is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.descriptors.is_empty()
    }

    /// Get all DLL names in the import table.
    ///
    /// Returns a vector of all DLL names that have import descriptors.
    /// The order is not guaranteed to be consistent.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::imports::NativeImports;
    ///
    /// let mut imports = NativeImports::new();
    /// imports.add_dll("kernel32.dll")?;
    /// imports.add_dll("user32.dll")?;
    ///
    /// let dll_names = imports.get_dll_names();
    /// assert_eq!(dll_names.len(), 2);
    /// assert!(dll_names.contains(&"kernel32.dll".to_string()));
    /// assert!(dll_names.contains(&"user32.dll".to_string()));
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn get_dll_names(&self) -> Vec<String> {
        self.descriptors.keys().cloned().collect()
    }

    /// Generate import table data for PE writing.
    ///
    /// Creates the complete import table structure including import descriptors,
    /// Import Lookup Table (ILT), Import Address Table (IAT), and name tables.
    /// The returned data can be written directly to a PE file's import section.
    ///
    /// # Arguments
    /// * `is_pe32_plus` - Whether this is PE32+ format (64-bit) or PE32 (32-bit)
    ///
    /// # Returns
    ///
    /// A `Result` containing a vector with the complete import table data in PE format,
    /// or an empty vector if no imports are present. Returns an error if the table
    /// generation fails due to size limitations or other constraints.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::imports::NativeImports;
    ///
    /// let mut imports = NativeImports::new();
    /// imports.add_dll("kernel32.dll")?;
    /// imports.add_function("kernel32.dll", "GetCurrentProcessId")?;
    ///
    /// let table_data = imports.get_import_table_data(false)?; // PE32 format
    /// assert!(!table_data.is_empty());
    /// println!("Import table size: {} bytes", table_data.len());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The calculated table size would exceed reasonable limits
    /// - String writing operations fail due to encoding issues
    /// - Memory allocation for the output buffer fails
    ///
    /// # Table Layout
    ///
    /// The generated data follows this structure:
    /// 1. Import Descriptor Table (null-terminated)
    /// 2. Import Lookup Tables (ILT) for each DLL
    /// 3. Import Address Tables (IAT) for each DLL
    /// 4. Name table with function names and hints
    /// 5. DLL name strings
    pub fn get_import_table_data(&self, is_pe32_plus: bool) -> Result<Vec<u8>> {
        if self.is_empty() {
            return Ok(Vec::new());
        }

        // Calculate total size needed for the import table
        let descriptor_table_size = (self.descriptors.len() + 1) * 20; // +1 for null terminator

        // Calculate sizes for ILT and IAT tables
        let mut total_string_size = 0;

        for descriptor in self.descriptors.values() {
            total_string_size += descriptor.dll_name.len() + 1; // +1 for null terminator

            for function in &descriptor.functions {
                if let Some(ref name) = function.name {
                    total_string_size += 2 + name.len() + 1; // 2 bytes hint + name + null terminator
                }
            }
        }

        // Each DLL has ILT and IAT tables (function count + 1 null terminator)
        // Entry size depends on PE format: PE32 = 4 bytes, PE32+ = 8 bytes
        let entry_size = if is_pe32_plus { 8 } else { 4 };
        let mut ilt_iat_size = 0;
        for descriptor in self.descriptors.values() {
            let entries_per_table = descriptor.functions.len() + 1; // +1 for null terminator
            ilt_iat_size += entries_per_table * entry_size * 2; // * 2 for ILT and IAT
        }

        let estimated_size = descriptor_table_size + ilt_iat_size + total_string_size;

        // Allocate buffer with estimated size plus some padding
        let mut data = vec![0u8; estimated_size + 256];

        let mut offset = 0;

        // Calculate offsets for different sections
        let mut current_rva_offset = descriptor_table_size;

        // Build descriptors with calculated offsets
        // Sort ALL descriptors (including existing ones) by DLL name to ensure deterministic ordering
        let mut descriptors_sorted: Vec<_> = self.descriptors.values().collect();
        descriptors_sorted.sort_by(|a, b| a.dll_name.cmp(&b.dll_name));

        let mut descriptors_with_offsets = Vec::new();

        // First pass: Calculate ILT offsets (all ILTs come first)
        let ilt_start_offset = current_rva_offset;
        let mut ilt_offset = ilt_start_offset;

        for descriptor in descriptors_sorted {
            let mut desc = descriptor.clone();
            #[allow(clippy::cast_possible_truncation)]
            {
                desc.original_first_thunk = self.import_table_base_rva + (ilt_offset as u32);
            }
            ilt_offset += (descriptor.functions.len() + 1) * entry_size; // +1 for null terminator
            descriptors_with_offsets.push(desc);
        }

        // Second pass: Calculate IAT offsets (all IATs come after all ILTs)
        let iat_start_offset = ilt_offset;
        let mut iat_offset = iat_start_offset;

        for descriptor in &mut descriptors_with_offsets {
            #[allow(clippy::cast_possible_truncation)]
            {
                descriptor.first_thunk = self.import_table_base_rva + (iat_offset as u32);
            }
            iat_offset += (descriptor.functions.len() + 1) * entry_size; // +1 for null terminator
        }

        current_rva_offset = iat_offset;

        let strings_section_offset = current_rva_offset;
        let mut dll_name_rvas = Vec::new();
        let mut function_name_rvas: Vec<Vec<u64>> = Vec::new();
        let mut current_string_offset = strings_section_offset;

        // First pass: calculate DLL name RVAs
        for descriptor in &descriptors_with_offsets {
            #[allow(clippy::cast_possible_truncation)]
            let dll_name_rva = self.import_table_base_rva + (current_string_offset as u32);
            dll_name_rvas.push(dll_name_rva);
            current_string_offset += descriptor.dll_name.len() + 1; // +1 for null terminator
        }

        // Second pass: calculate function name RVAs
        for descriptor in &descriptors_with_offsets {
            let mut func_rvas = Vec::new();

            for function in &descriptor.functions {
                if let Some(ref name) = function.name {
                    #[allow(clippy::cast_possible_truncation)]
                    let func_name_rva = self.import_table_base_rva + (current_string_offset as u32);
                    func_rvas.push(u64::from(func_name_rva));
                    current_string_offset += 2; // hint (2 bytes)
                    current_string_offset += name.len() + 1; // name + null terminator
                }
            }

            function_name_rvas.push(func_rvas);
        }

        // Third pass: update ILT values in descriptors
        for (i, descriptor) in descriptors_with_offsets.iter_mut().enumerate() {
            let func_rvas = &function_name_rvas[i];
            let mut func_idx = 0;

            for function in &mut descriptor.functions {
                if function.name.is_some() {
                    // Named import: use RVA pointing to hint/name table entry
                    if func_idx < func_rvas.len() {
                        function.ilt_value = func_rvas[func_idx];
                        func_idx += 1;
                    }
                } else if let Some(ordinal) = function.ordinal {
                    // Ordinal import: use ordinal with high bit set
                    // PE32 uses bit 31, PE32+ uses bit 63
                    if is_pe32_plus {
                        function.ilt_value = 0x8000_0000_0000_0000u64 | u64::from(ordinal);
                    } else {
                        function.ilt_value = 0x8000_0000u64 | u64::from(ordinal);
                    }
                }
            }
        }

        // Write import descriptor table
        for (i, descriptor) in descriptors_with_offsets.iter().enumerate() {
            // Write IMAGE_IMPORT_DESCRIPTOR structure (20 bytes each)
            write_le_at::<u32>(&mut data, &mut offset, descriptor.original_first_thunk)?;
            write_le_at::<u32>(&mut data, &mut offset, descriptor.timestamp)?;
            write_le_at::<u32>(&mut data, &mut offset, descriptor.forwarder_chain)?;
            write_le_at::<u32>(&mut data, &mut offset, dll_name_rvas[i])?; // DLL name RVA
            write_le_at::<u32>(&mut data, &mut offset, descriptor.first_thunk)?;
        }

        // Write null terminator descriptor (20 bytes of zeros)
        for _ in 0..5 {
            write_le_at::<u32>(&mut data, &mut offset, 0)?;
        }

        // Write ALL ILT tables first (not interleaved - this is required by PE format)
        for descriptor in &descriptors_with_offsets {
            // Write ILT for this DLL (entry size depends on PE format)
            for function in &descriptor.functions {
                if is_pe32_plus {
                    write_le_at::<u64>(&mut data, &mut offset, function.ilt_value)?;
                } else {
                    #[allow(clippy::cast_possible_truncation)]
                    {
                        write_le_at::<u32>(&mut data, &mut offset, function.ilt_value as u32)?;
                    }
                }
            }
            // Null terminator for this DLL's ILT
            if is_pe32_plus {
                write_le_at::<u64>(&mut data, &mut offset, 0)?;
            } else {
                write_le_at::<u32>(&mut data, &mut offset, 0)?;
            }
        }

        // Write ALL IAT tables after all ILTs (required by PE format)
        for descriptor in &descriptors_with_offsets {
            // Write IAT for this DLL (initially same as ILT, entry size depends on PE format)
            for function in &descriptor.functions {
                if is_pe32_plus {
                    write_le_at::<u64>(&mut data, &mut offset, function.ilt_value)?;
                } else {
                    #[allow(clippy::cast_possible_truncation)]
                    {
                        write_le_at::<u32>(&mut data, &mut offset, function.ilt_value as u32)?;
                    }
                }
            }
            // Null terminator for this DLL's IAT
            if is_pe32_plus {
                write_le_at::<u64>(&mut data, &mut offset, 0)?;
            } else {
                write_le_at::<u32>(&mut data, &mut offset, 0)?;
            }
        }

        // First, write all DLL names
        for descriptor in &descriptors_with_offsets {
            write_string_at(&mut data, &mut offset, &descriptor.dll_name)?;
        }

        // Then, write all function names with hints
        for descriptor in &descriptors_with_offsets {
            for function in &descriptor.functions {
                if let Some(ref name) = function.name {
                    // Write hint (2 bytes)
                    write_le_at::<u16>(&mut data, &mut offset, function.hint)?;
                    // Write function name
                    write_string_at(&mut data, &mut offset, name)?;
                }
            }
        }

        // Truncate buffer to actual used size
        data.truncate(offset);

        Ok(data)
    }

    /// Update Import Address Table RVAs after section moves.
    ///
    /// Adjusts all IAT RVAs by the specified delta when sections are moved
    /// during PE layout changes. Essential for maintaining valid references
    /// after assembly modifications.
    ///
    /// # Arguments
    /// * `rva_delta` - The signed offset to apply to all RVAs
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::imports::NativeImports;
    ///
    /// let mut imports = NativeImports::new();
    /// imports.add_dll("kernel32.dll")?;
    /// imports.add_function("kernel32.dll", "GetCurrentProcessId")?;
    ///
    /// // Section moved up by 0x1000 bytes
    /// imports.update_iat_rvas(0x1000)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the RVA delta would cause integer overflow or
    /// result in invalid RVA values.
    pub fn update_iat_rvas(&mut self, rva_delta: i64) -> Result<()> {
        let mut updated_entries = HashMap::new();

        for (old_rva, mut entry) in self.iat_entries.drain() {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let new_rva = if rva_delta >= 0 {
                old_rva.checked_add(rva_delta as u32)
            } else {
                old_rva.checked_sub((-rva_delta) as u32)
            };

            match new_rva {
                Some(rva) => {
                    entry.rva = rva;
                    updated_entries.insert(rva, entry);
                }
                None => {
                    return Err(Error::Error("RVA delta would cause overflow".to_string()));
                }
            }
        }

        self.iat_entries = updated_entries;

        for descriptor in self.descriptors.values_mut() {
            for function in &mut descriptor.functions {
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                let new_rva = if rva_delta >= 0 {
                    function.rva.checked_add(rva_delta as u32)
                } else {
                    function.rva.checked_sub((-rva_delta) as u32)
                };

                match new_rva {
                    Some(rva) => function.rva = rva,
                    None => {
                        return Err(Error::Error("RVA delta would cause overflow".to_string()));
                    }
                }
            }
        }

        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let new_next_rva = if rva_delta >= 0 {
            self.next_iat_rva.checked_add(rva_delta as u32)
        } else {
            self.next_iat_rva.checked_sub((-rva_delta) as u32)
        };

        match new_next_rva {
            Some(rva) => self.next_iat_rva = rva,
            None => {
                return Err(Error::Error("RVA delta would cause overflow".to_string()));
            }
        }

        Ok(())
    }

    /// Set the base RVA for import table generation.
    ///
    /// This must be called before `get_import_table_data()` to ensure that
    /// all RVA calculations in the import table are based on the correct
    /// final location where the table will be written in the PE file.
    ///
    /// # Arguments
    /// * `base_rva` - The RVA where the import table will be placed in the final PE file
    pub fn set_import_table_base_rva(&mut self, base_rva: u32) {
        self.import_table_base_rva = base_rva;
    }

    /// Allocate a new IAT RVA.
    ///
    /// Returns the next available RVA for IAT allocation and increments
    /// the internal counter. Used internally when adding new function imports.
    fn allocate_iat_rva(&mut self) -> u32 {
        let rva = self.next_iat_rva;
        self.next_iat_rva += 4; // Each IAT entry is 4 bytes (PE32) - TODO: make this configurable for PE32+
        rva
    }
}

impl Default for NativeImports {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_native_imports_is_empty() {
        let imports = NativeImports::new();
        assert!(imports.is_empty());
        assert_eq!(imports.dll_count(), 0);
    }

    #[test]
    fn add_dll_works() {
        let mut imports = NativeImports::new();

        imports.add_dll("kernel32.dll").unwrap();
        assert!(!imports.is_empty());
        assert_eq!(imports.dll_count(), 1);
        assert!(imports.has_dll("kernel32.dll"));

        // Adding same DLL again should not increase count
        imports.add_dll("kernel32.dll").unwrap();
        assert_eq!(imports.dll_count(), 1);
    }

    #[test]
    fn test_import_table_string_layout_fix() {
        let mut imports = NativeImports::new();
        imports.set_import_table_base_rva(0x2000);

        // Add DLLs - the fix ensures deterministic ordering
        imports.add_dll("user32.dll").unwrap();
        imports.add_function("user32.dll", "MessageBoxA").unwrap();

        imports.add_dll("kernel32.dll").unwrap();
        imports
            .add_function("kernel32.dll", "GetCurrentProcessId")
            .unwrap();

        // Generate import table data - this should not crash and should be deterministic
        let table_data1 = imports.get_import_table_data(false).unwrap(); // PE32
        let table_data2 = imports.get_import_table_data(false).unwrap(); // PE32

        // Critical fix: The output is now deterministic (no HashMap iteration randomness)
        assert_eq!(
            table_data1, table_data2,
            "Import table generation should be deterministic"
        );

        // Verify basic properties
        assert!(!table_data1.is_empty());
        assert!(table_data1.len() > 100); // Should contain substantial data
    }

    #[test]
    fn test_ilt_multiple_functions_per_dll() {
        let mut imports = NativeImports::new();
        imports.set_import_table_base_rva(0x2000);

        // Test the specific issue: multiple functions per DLL should all be parseable
        // Add user32.dll with 2 functions (should both be parsed)
        imports.add_dll("user32.dll").unwrap();
        imports.add_function("user32.dll", "MessageBoxW").unwrap();
        imports
            .add_function("user32.dll", "GetWindowTextW")
            .unwrap();

        // Add kernel32.dll with 2 functions (should both be parsed)
        imports.add_dll("kernel32.dll").unwrap();
        imports
            .add_function("kernel32.dll", "GetCurrentProcessId")
            .unwrap();
        imports.add_function("kernel32.dll", "ExitProcess").unwrap();

        // Add mscoree.dll with 1 function (baseline)
        imports.add_dll("mscoree.dll").unwrap();
        imports.add_function("mscoree.dll", "_CorExeMain").unwrap();

        // Verify that each DLL has the correct number of functions
        assert_eq!(
            imports
                .get_descriptor("user32.dll")
                .unwrap()
                .functions
                .len(),
            2
        );
        assert_eq!(
            imports
                .get_descriptor("kernel32.dll")
                .unwrap()
                .functions
                .len(),
            2
        );
        assert_eq!(
            imports
                .get_descriptor("mscoree.dll")
                .unwrap()
                .functions
                .len(),
            1
        );

        // Generate import table data - this should calculate ILT values
        let table_data = imports.get_import_table_data(false).unwrap(); // PE32
        assert!(!table_data.is_empty());

        // The key test: verify that the table data contains entries for all functions
        // Import descriptors: 3 DLLs + null terminator = 4 * 20 = 80 bytes
        // ILT tables: kernel32(2+1)*8 + mscoree(1+1)*8 + user32(2+1)*8 = 48 bytes
        // IAT tables: same as ILT = 48 bytes
        // Strings: Variable but should be substantial
        let expected_min_size = 80 + 48 + 48; // At least this much without strings
        assert!(
            table_data.len() >= expected_min_size,
            "Table data should be at least {} bytes, got {}",
            expected_min_size,
            table_data.len()
        );

        // Verify that the import descriptors section contains valid RVAs
        // Each import descriptor is 20 bytes: OriginalFirstThunk, TimeDateStamp, ForwarderChain, Name, FirstThunk
        for i in 0..3 {
            // 3 DLLs
            let desc_offset = i * 20;
            if desc_offset + 20 <= table_data.len() {
                let original_first_thunk = u32::from_le_bytes([
                    table_data[desc_offset],
                    table_data[desc_offset + 1],
                    table_data[desc_offset + 2],
                    table_data[desc_offset + 3],
                ]);
                let first_thunk = u32::from_le_bytes([
                    table_data[desc_offset + 16],
                    table_data[desc_offset + 17],
                    table_data[desc_offset + 18],
                    table_data[desc_offset + 19],
                ]);

                // Both should be non-zero RVAs pointing to ILT and IAT respectively
                assert_ne!(
                    original_first_thunk, 0,
                    "OriginalFirstThunk should be non-zero for descriptor {i}"
                );
                assert_ne!(
                    first_thunk, 0,
                    "FirstThunk should be non-zero for descriptor {i}"
                );
            }
        }

        // Verify function counts
        assert_eq!(
            imports
                .get_descriptor("user32.dll")
                .unwrap()
                .functions
                .len(),
            2
        );
        assert_eq!(
            imports
                .get_descriptor("kernel32.dll")
                .unwrap()
                .functions
                .len(),
            2
        );
        assert_eq!(
            imports
                .get_descriptor("mscoree.dll")
                .unwrap()
                .functions
                .len(),
            1
        );
    }
}
