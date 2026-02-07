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
//! use dotscope::metadata::imports::NativeImports;
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
//! ```rust,no_run
//! use dotscope::metadata::imports::NativeImports;
//!
//! # fn main() -> dotscope::Result<()> {
//! let mut imports = NativeImports::new();
//!
//! // Add DLL and functions
//! imports.add_dll("kernel32.dll")?;
//! imports.add_function("kernel32.dll", "GetCurrentProcessId")?;
//! imports.add_function("kernel32.dll", "ExitProcess")?;
//!
//! imports.add_dll("user32.dll")?;
//! imports.add_function_by_ordinal("user32.dll", 120)?; // MessageBoxW
//! # Ok(())
//! # }
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
    Result,
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
/// ```rust,no_run
/// use dotscope::metadata::imports::NativeImports;
///
/// # fn main() -> dotscope::Result<()> {
/// let mut imports = NativeImports::new();
///
/// // Add a DLL dependency
/// imports.add_dll("kernel32.dll")?;
/// imports.add_function("kernel32.dll", "GetCurrentProcessId")?;
///
/// println!("DLL count: {}", imports.dll_count());
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct NativeImports {
    /// Import descriptors indexed by DLL name for fast lookup
    descriptors: HashMap<String, ImportDescriptor>,

    /// Import Address Table entries indexed by RVA
    iat_entries: HashMap<u32, ImportAddressEntry>,

    /// Next available RVA for IAT allocation
    next_iat_rva: u32,

    /// Whether this is a PE32+ (64-bit) image.
    /// Affects IAT entry size: 4 bytes for PE32, 8 bytes for PE32+.
    is_pe32_plus: bool,
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
            next_iat_rva: 0x1000, // Default IAT base address
            is_pe32_plus: false,  // Default to PE32 (32-bit)
        }
    }

    /// Sets whether this is a PE32+ (64-bit) image.
    ///
    /// This affects the IAT entry size:
    /// - PE32 (32-bit): 4 bytes per entry
    /// - PE32+ (64-bit): 8 bytes per entry
    ///
    /// # Arguments
    /// * `is_pe32_plus` - `true` for 64-bit PE32+, `false` for 32-bit PE32
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::imports::NativeImports;
    ///
    /// let mut imports = NativeImports::new();
    /// imports.set_pe_format(true); // Configure for 64-bit
    /// assert!(imports.is_pe32_plus());
    /// ```
    pub fn set_pe_format(&mut self, is_pe32_plus: bool) {
        self.is_pe32_plus = is_pe32_plus;
    }

    /// Returns whether this is configured for PE32+ (64-bit) format.
    ///
    /// # Returns
    /// `true` if configured for PE32+ (64-bit), `false` for PE32 (32-bit).
    #[must_use]
    pub fn is_pe32_plus(&self) -> bool {
        self.is_pe32_plus
    }

    /// Returns the IAT entry size in bytes based on the PE format.
    ///
    /// # Returns
    /// - 4 bytes for PE32 (32-bit)
    /// - 8 bytes for PE32+ (64-bit)
    #[must_use]
    pub fn iat_entry_size(&self) -> u32 {
        if self.is_pe32_plus {
            8
        } else {
            4
        }
    }

    /// Creates native imports directly from PE import data.
    ///
    /// # Arguments
    /// * `pe_imports` - Slice of PE import entries to process
    /// * `is_pe32_plus` - `true` for PE32+ (64-bit), `false` for PE32 (32-bit)
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
    /// // For 32-bit PE files
    /// let native_imports = NativeImports::from_pe_imports(&pe_imports, false)?;
    /// assert_eq!(native_imports.dll_count(), 1);
    ///
    /// // For 64-bit PE files
    /// let native_imports_64 = NativeImports::from_pe_imports(&pe_imports, true)?;
    /// assert!(native_imports_64.is_pe32_plus());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn from_pe_imports(pe_imports: &[Import], is_pe32_plus: bool) -> Result<Self> {
        let mut native = Self::new();
        native.is_pe32_plus = is_pe32_plus;

        let mut imports_by_dll: HashMap<&str, Vec<&Import>> = HashMap::new();
        for import in pe_imports {
            imports_by_dll.entry(&import.dll).or_default().push(import);
        }

        for (dll_name, dll_imports) in imports_by_dll {
            let dll_name_owned = dll_name.to_owned();

            let mut descriptor = ImportDescriptor {
                dll_name: dll_name_owned.clone(),
                original_first_thunk: 0,
                first_thunk: 0,
                functions: Vec::with_capacity(dll_imports.len()),
                timestamp: 0,
                forwarder_chain: 0,
            };

            for pe_import in dll_imports {
                let function_identifier = Self::build_function_identifier(pe_import);

                native.iat_entries.insert(
                    pe_import.rva,
                    ImportAddressEntry {
                        rva: pe_import.rva,
                        dll_name: dll_name_owned.clone(),
                        function_identifier,
                        original_value: 0,
                    },
                );

                descriptor.functions.push(pe_import.clone());
            }

            native.descriptors.insert(dll_name_owned, descriptor);
        }

        Ok(native)
    }

    /// Builds a function identifier string from an import entry.
    ///
    /// Returns the function name if available, otherwise formats the ordinal,
    /// or "unknown" if neither is available.
    fn build_function_identifier(import: &Import) -> String {
        if let Some(ref name) = import.name {
            if !name.is_empty() {
                return name.clone();
            }
        }
        import
            .ordinal
            .map_or_else(|| "unknown".to_string(), |ord| format!("#{ord}"))
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
    /// ```rust,no_run
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
            return Err(malformed_error!("DLL name cannot be empty"));
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
    /// ```rust,no_run
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
            return Err(malformed_error!("Function name cannot be empty"));
        }

        if let Some(descriptor) = self.descriptors.get(dll_name) {
            if descriptor
                .functions
                .iter()
                .any(|f| f.name.as_deref() == Some(function_name))
            {
                return Err(malformed_error!(
                    "Function '{function_name}' already imported from '{dll_name}'"
                ));
            }
        } else {
            return Err(malformed_error!(
                "DLL '{dll_name}' not found in import table"
            ));
        }

        let iat_rva = self.allocate_iat_rva();

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

        let descriptor = self
            .descriptors
            .get_mut(dll_name)
            .ok_or_else(|| malformed_error!("DLL '{dll_name}' disappeared from import table"))?;
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
    /// ```rust,no_run
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
            return Err(malformed_error!("Ordinal cannot be 0"));
        }

        if let Some(descriptor) = self.descriptors.get(dll_name) {
            if descriptor
                .functions
                .iter()
                .any(|f| f.ordinal == Some(ordinal))
            {
                return Err(malformed_error!(
                    "Ordinal {ordinal} already imported from '{dll_name}'"
                ));
            }
        } else {
            return Err(malformed_error!(
                "DLL '{dll_name}' not found in import table"
            ));
        }

        let iat_rva = self.allocate_iat_rva();
        let descriptor = self
            .descriptors
            .get_mut(dll_name)
            .ok_or_else(|| malformed_error!("DLL '{dll_name}' disappeared from import table"))?;

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
    /// ```rust,no_run
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
    /// ```rust,no_run
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
    /// ```rust,no_run
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
    /// ```rust,no_run
    /// use dotscope::metadata::imports::NativeImports;
    ///
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
    /// ```rust,no_run
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
    /// ```rust,no_run
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
                    return Err(malformed_error!("RVA delta would cause overflow"));
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
                        return Err(malformed_error!("RVA delta would cause overflow"));
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
                return Err(malformed_error!("RVA delta would cause overflow"));
            }
        }

        Ok(())
    }

    /// Allocate a new IAT RVA.
    ///
    /// Returns the next available RVA for IAT allocation and increments
    /// the internal counter by the appropriate entry size (4 bytes for PE32,
    /// 8 bytes for PE32+). Used internally when adding new function imports.
    fn allocate_iat_rva(&mut self) -> u32 {
        let rva = self.next_iat_rva;
        self.next_iat_rva += self.iat_entry_size();
        rva
    }

    /// Calculate the total size of the Import Address Table (IAT) in bytes.
    ///
    /// For .NET PE files, the IAT is placed at the start of the .text section.
    /// Each DLL's imports require (function_count + 1) entries for the null terminator.
    ///
    /// # Arguments
    /// * `is_pe32_plus` - Whether this is PE32+ (64-bit) or PE32 (32-bit) format
    ///
    /// # Returns
    /// Total IAT size in bytes.
    #[must_use]
    pub fn iat_byte_size(&self, is_pe32_plus: bool) -> usize {
        let entry_size = if is_pe32_plus { 8 } else { 4 };
        let mut total_entries = 0;

        for descriptor in self.descriptors.values() {
            // Each DLL needs: function entries + 1 null terminator
            total_entries += descriptor.functions.len() + 1;
        }

        total_entries * entry_size
    }

    /// Build the IAT (Import Address Table) bytes for .NET PE generation.
    ///
    /// Generates the IAT content that should be written at the start of the .text section.
    /// Each entry contains an RVA pointing to the hint/name table entry for that function.
    /// The RVAs are calculated based on the provided `import_table_rva` parameter which
    /// indicates where the import table (containing the strings) will be located.
    ///
    /// # Arguments
    /// * `is_pe32_plus` - Whether this is PE32+ (64-bit) or PE32 (32-bit) format
    /// * `import_table_rva` - RVA where the import table will be written (used to calculate string RVAs)
    ///
    /// # Returns
    /// IAT bytes to write at the start of .text section.
    pub fn build_iat_bytes(&self, is_pe32_plus: bool, import_table_rva: u32) -> Result<Vec<u8>> {
        if self.is_empty() {
            return Ok(Vec::new());
        }

        let entry_size = if is_pe32_plus { 8 } else { 4 };
        let mut iat_bytes = Vec::with_capacity(self.iat_byte_size(is_pe32_plus));

        // Sort descriptors for deterministic ordering (mscoree.dll should be first when building import list)
        let mut descriptors_sorted: Vec<_> = self.descriptors.values().collect();
        descriptors_sorted
            .sort_by(|a, b| a.dll_name.to_lowercase().cmp(&b.dll_name.to_lowercase()));

        // Calculate where strings will be in the import table
        // Layout: descriptors + null descriptor + ILT entries + strings
        let descriptor_size = (self.descriptors.len() + 1) * 20; // +1 for null terminator

        let mut total_ilt_entries = 0;
        for desc in &descriptors_sorted {
            total_ilt_entries += desc.functions.len() + 1; // +1 for null terminator per DLL
        }
        let ilt_size = total_ilt_entries * entry_size;

        // Strings start after descriptors and ILT
        let strings_start_rva = import_table_rva + (descriptor_size + ilt_size) as u32;

        // Calculate hint/name RVAs for each function
        let mut current_string_rva = strings_start_rva;

        // First pass: calculate DLL name RVAs (they come first in strings)
        let mut dll_name_end_rva = current_string_rva;
        for desc in &descriptors_sorted {
            dll_name_end_rva += (desc.dll_name.len() + 1) as u32; // +1 for null terminator
        }

        // Function hint/names come after DLL names
        current_string_rva = dll_name_end_rva;

        // Build IAT entries for each DLL
        for descriptor in &descriptors_sorted {
            for function in &descriptor.functions {
                let thunk_value = if let Some(ordinal) = function.ordinal {
                    // Ordinal import: high bit set + ordinal
                    if function.name.is_none() {
                        if is_pe32_plus {
                            0x8000_0000_0000_0000u64 | u64::from(ordinal)
                        } else {
                            0x8000_0000u64 | u64::from(ordinal)
                        }
                    } else {
                        // Named import with hint
                        u64::from(current_string_rva)
                    }
                } else {
                    // Named import
                    u64::from(current_string_rva)
                };

                // Write IAT entry
                if is_pe32_plus {
                    iat_bytes.extend_from_slice(&thunk_value.to_le_bytes());
                } else {
                    #[allow(clippy::cast_possible_truncation)]
                    iat_bytes.extend_from_slice(&(thunk_value as u32).to_le_bytes());
                }

                // Advance string RVA for named imports
                if let Some(function_name) = function.name.as_ref() {
                    current_string_rva += 2; // hint (2 bytes)
                    current_string_rva += (function_name.len() + 1) as u32;
                    // name + null
                }
            }

            // Null terminator for this DLL's IAT
            if is_pe32_plus {
                iat_bytes.extend_from_slice(&0u64.to_le_bytes());
            } else {
                iat_bytes.extend_from_slice(&0u32.to_le_bytes());
            }
        }

        Ok(iat_bytes)
    }

    /// Build the import table data (descriptors + ILT + strings) for .NET PE generation.
    ///
    /// Generates import table data where FirstThunk fields point to the external IAT
    /// at `iat_rva` (typically at the start of .text section). This method does NOT
    /// generate an embedded IAT - only descriptors, ILT, and strings.
    ///
    /// # Arguments
    /// * `is_pe32_plus` - Whether this is PE32+ (64-bit) or PE32 (32-bit) format
    /// * `iat_rva` - RVA where the IAT is located (start of .text section)
    /// * `table_rva` - RVA where this import table will be written
    ///
    /// # Returns
    /// Import table bytes (descriptors + ILT + strings) to write after metadata.
    pub fn build_import_table(
        &self,
        is_pe32_plus: bool,
        iat_rva: u32,
        table_rva: u32,
    ) -> Result<Vec<u8>> {
        if self.is_empty() {
            return Ok(Vec::new());
        }

        let entry_size = if is_pe32_plus { 8 } else { 4 };

        // Sort descriptors for deterministic ordering
        let mut descriptors_sorted: Vec<_> = self.descriptors.values().collect();
        descriptors_sorted
            .sort_by(|a, b| a.dll_name.to_lowercase().cmp(&b.dll_name.to_lowercase()));

        // Calculate layout sizes
        let descriptor_table_size = (descriptors_sorted.len() + 1) * 20; // +1 for null terminator

        // Calculate total ILT size
        let mut total_ilt_entries = 0;
        for desc in &descriptors_sorted {
            total_ilt_entries += desc.functions.len() + 1; // +1 for null terminator per DLL
        }
        let ilt_size = total_ilt_entries * entry_size;

        // Calculate total string size
        let mut total_string_size = 0;
        for desc in &descriptors_sorted {
            total_string_size += desc.dll_name.len() + 1; // DLL name + null
            for func in &desc.functions {
                if let Some(ref name) = func.name {
                    total_string_size += 2 + name.len() + 1; // hint + name + null
                }
            }
        }

        // Allocate buffer
        let total_size = descriptor_table_size + ilt_size + total_string_size + 16; // +16 for alignment padding
        let mut data = vec![0u8; total_size];
        let mut offset = 0;

        // Calculate RVAs
        let ilt_start_rva = table_rva + descriptor_table_size as u32;
        let strings_start_rva = ilt_start_rva + ilt_size as u32;

        // Build ILT offset map and string RVAs
        let mut ilt_rva = ilt_start_rva;
        let mut iat_offset = 0u32; // Offset within IAT for each DLL

        // Pre-calculate DLL name RVAs
        let mut dll_name_rvas = Vec::with_capacity(descriptors_sorted.len());
        let mut current_dll_name_rva = strings_start_rva;
        for desc in &descriptors_sorted {
            dll_name_rvas.push(current_dll_name_rva);
            current_dll_name_rva += (desc.dll_name.len() + 1) as u32;
        }

        // Pre-calculate function name RVAs
        let mut current_func_name_rva = current_dll_name_rva;
        let mut func_name_rvas: Vec<Vec<u64>> = Vec::with_capacity(descriptors_sorted.len());

        for desc in &descriptors_sorted {
            let mut rvas = Vec::with_capacity(desc.functions.len());
            for func in &desc.functions {
                if let Some(function_name) = func.name.as_ref() {
                    rvas.push(u64::from(current_func_name_rva));
                    current_func_name_rva += 2; // hint
                    current_func_name_rva += (function_name.len() + 1) as u32;
                // name + null
                } else {
                    rvas.push(0); // Will use ordinal
                }
            }
            func_name_rvas.push(rvas);
        }

        // Write import descriptors
        for (i, desc) in descriptors_sorted.iter().enumerate() {
            let desc_ilt_rva = ilt_rva;
            let desc_iat_rva = iat_rva + iat_offset;

            // OriginalFirstThunk (ILT RVA)
            write_le_at::<u32>(&mut data, &mut offset, desc_ilt_rva)?;
            // TimeDateStamp
            write_le_at::<u32>(&mut data, &mut offset, 0)?;
            // ForwarderChain
            write_le_at::<u32>(&mut data, &mut offset, 0)?;
            // Name (DLL name RVA)
            write_le_at::<u32>(&mut data, &mut offset, dll_name_rvas[i])?;
            // FirstThunk (IAT RVA - points to external IAT)
            write_le_at::<u32>(&mut data, &mut offset, desc_iat_rva)?;

            // Update offsets for next descriptor
            let entries_for_dll = desc.functions.len() + 1; // +1 for null terminator
            ilt_rva += (entries_for_dll * entry_size) as u32;
            iat_offset += (entries_for_dll * entry_size) as u32;
        }

        // Write null terminator descriptor
        for _ in 0..5 {
            write_le_at::<u32>(&mut data, &mut offset, 0)?;
        }

        // Write ILT entries
        for (i, desc) in descriptors_sorted.iter().enumerate() {
            for (j, func) in desc.functions.iter().enumerate() {
                let ilt_value = if func.name.is_none() {
                    // Ordinal import
                    if let Some(ordinal) = func.ordinal {
                        if is_pe32_plus {
                            0x8000_0000_0000_0000u64 | u64::from(ordinal)
                        } else {
                            0x8000_0000u64 | u64::from(ordinal)
                        }
                    } else {
                        0
                    }
                } else {
                    // Named import - use pre-calculated RVA
                    func_name_rvas[i][j]
                };

                if is_pe32_plus {
                    write_le_at::<u64>(&mut data, &mut offset, ilt_value)?;
                } else {
                    #[allow(clippy::cast_possible_truncation)]
                    write_le_at::<u32>(&mut data, &mut offset, ilt_value as u32)?;
                }
            }

            // Null terminator for this DLL's ILT
            if is_pe32_plus {
                write_le_at::<u64>(&mut data, &mut offset, 0)?;
            } else {
                write_le_at::<u32>(&mut data, &mut offset, 0)?;
            }
        }

        // Write strings: DLL names first, then function names
        for desc in &descriptors_sorted {
            write_string_at(&mut data, &mut offset, &desc.dll_name)?;
        }

        for desc in &descriptors_sorted {
            for func in &desc.functions {
                if let Some(ref name) = func.name {
                    // Write hint (2 bytes)
                    write_le_at::<u16>(&mut data, &mut offset, func.hint)?;
                    // Write function name
                    write_string_at(&mut data, &mut offset, name)?;
                }
            }
        }

        // Align to 4 bytes
        while offset % 4 != 0 {
            if offset < data.len() {
                data[offset] = 0;
            }
            offset += 1;
        }

        // Truncate to actual size
        data.truncate(offset);

        Ok(data)
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
}
