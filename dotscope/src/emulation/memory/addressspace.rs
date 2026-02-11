//! Unified address space management for CIL emulation.
//!
//! This module provides the [`AddressSpace`] type, which offers a unified view of all memory
//! in an emulated .NET process. It combines multiple memory subsystems:
//!
//! - **Managed heap** ([`SharedHeap`]) - Objects, arrays, and strings allocated via `newobj`, `newarr`, etc.
//! - **Memory regions** ([`MemoryRegion`](super::MemoryRegion)) - PE images, mapped data, and unmanaged allocations
//! - **Static fields** ([`StaticFieldStorage`](super::StaticFieldStorage)) - Static field values shared across threads
//!
//! # Shared Heap Semantics
//!
//! The managed heap is wrapped in [`SharedHeap`], which uses `Arc<ManagedHeap>` internally.
//! This enables cheap cloning and sharing across threads while maintaining reference semantics
//! for heap objects.
//!
//! # Example
//!
//! ```rust
//! use dotscope::emulation::AddressSpace;
//!
//! // Create a new address space with default settings (64MB heap, 4GB address space)
//! let space = AddressSpace::new();
//!
//! // Allocate a string on the managed heap
//! let string_ref = space.alloc_string("Hello, World!").unwrap();
//!
//! // Map raw data at a specific address
//! space.map_data(0x1000, &[0xDE, 0xAD, 0xBE, 0xEF], "test_data").unwrap();
//!
//! // Read back the data
//! let data = space.read(0x1000, 4).unwrap();
//! assert_eq!(data, vec![0xDE, 0xAD, 0xBE, 0xEF]);
//! ```

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, RwLock,
};

use imbl::HashMap as ImHashMap;

use crate::{
    emulation::{
        memory::{
            region::{MemoryProtection, MemoryRegion, SectionInfo},
            statics::StaticFieldStorage,
        },
        EmValue, EmulationError, HeapRef, ManagedHeap,
    },
    metadata::token::Token,
    Error, Result,
};

/// Shared managed heap wrapper for thread-safe heap access.
///
/// `SharedHeap` wraps a [`ManagedHeap`] in an `Arc`, enabling cheap cloning and
/// sharing across threads and method calls. Multiple [`AddressSpace`] instances
/// can share the same heap, allowing objects allocated in one context to be
/// visible in another.
///
/// # Thread Safety
///
/// The underlying [`ManagedHeap`] uses interior mutability via `RwLock`, so
/// `SharedHeap` can be safely shared across threads with just `Clone`.
///
/// # Example
///
/// ```rust
/// use dotscope::emulation::SharedHeap;
///
/// let heap = SharedHeap::new(64 * 1024 * 1024); // 64MB
/// let heap2 = heap.clone(); // Cheap clone, shares same underlying heap
///
/// // Allocate in one clone
/// let str_ref = heap.alloc_string("shared").unwrap();
///
/// // Visible in the other
/// let s = heap2.get_string(str_ref).unwrap();
/// assert_eq!(&*s, "shared");
/// ```
#[derive(Clone, Debug)]
pub struct SharedHeap {
    inner: Arc<ManagedHeap>,
}

impl SharedHeap {
    /// Creates a new shared heap with the given size limit.
    ///
    /// # Arguments
    ///
    /// * `max_size` - Maximum heap size in bytes
    ///
    /// # Example
    ///
    /// ```rust
    /// use dotscope::emulation::SharedHeap;
    ///
    /// let heap = SharedHeap::new(1024 * 1024); // 1MB heap
    /// ```
    #[must_use]
    pub fn new(max_size: usize) -> Self {
        Self {
            inner: Arc::new(ManagedHeap::new(max_size)),
        }
    }

    /// Creates a shared heap from an existing [`ManagedHeap`].
    ///
    /// This wraps the given heap in an `Arc` for shared access.
    ///
    /// # Arguments
    ///
    /// * `heap` - The managed heap to wrap
    pub fn from_heap(heap: ManagedHeap) -> Self {
        Self {
            inner: Arc::new(heap),
        }
    }

    /// Returns a reference to the underlying [`ManagedHeap`].
    ///
    /// This provides direct access to the heap for operations not exposed
    /// through the `Deref` implementation.
    #[must_use]
    pub fn heap(&self) -> &ManagedHeap {
        &self.inner
    }

    /// Returns the number of strong references to this heap.
    ///
    /// Useful for debugging and understanding sharing patterns.
    #[must_use]
    pub fn ref_count(&self) -> usize {
        Arc::strong_count(&self.inner)
    }

    /// Returns `true` if this is the only reference to the heap.
    ///
    /// When unique, the heap can be safely modified without affecting
    /// other users.
    #[must_use]
    pub fn is_unique(&self) -> bool {
        Arc::strong_count(&self.inner) == 1
    }

    /// Forks this heap, creating an independent copy with CoW semantics.
    ///
    /// The forked heap shares its data structure with the original via
    /// structural sharing (using `imbl`). Both heaps can be modified
    /// independently - only the modified entries are copied.
    ///
    /// # Performance
    ///
    /// This is an O(1) operation due to `imbl`'s structural sharing.
    ///
    /// # Note
    ///
    /// Unlike `clone()` which shares the same heap via `Arc`, `fork()`
    /// creates a truly independent heap that starts with the same data
    /// but diverges on modification.
    #[must_use]
    pub fn fork(&self) -> Self {
        Self {
            inner: Arc::new(self.inner.fork()),
        }
    }
}

impl Default for SharedHeap {
    fn default() -> Self {
        Self::new(64 * 1024 * 1024) // 64 MB default
    }
}

impl std::ops::Deref for SharedHeap {
    type Target = ManagedHeap;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// Unified address space for an emulated .NET process.
///
/// `AddressSpace` provides a complete view of all memory accessible to an emulated
/// .NET process, integrating:
///
/// - **Managed heap** - Objects, arrays, and strings (via [`SharedHeap`])
/// - **Memory regions** - PE images, mapped data, and unmanaged allocations
/// - **Static fields** - Type-level static field storage
///
/// # Memory Layout
///
/// The address space has a configurable size (default 4GB). Automatic allocations
/// start at address `0x1000_0000` (256MB) and grow upward. PE images should be
/// mapped at their preferred base addresses using [`map_pe_image`](Self::map_pe_image).
///
/// # Thread Safety
///
/// The address space uses interior mutability for thread-safe access:
/// - Heap operations use `RwLock` internally
/// - Region operations are protected by a `RwLock`
/// - Static fields use `RwLock` for concurrent access
///
/// # Cloning Semantics
///
/// When cloned, the heap is shared (via `Arc`), but regions are copied.
/// This means heap objects are visible across clones, but region mappings
/// are independent.
///
/// # Example
///
/// ```rust
/// use dotscope::emulation::{AddressSpace, EmValue};
/// use dotscope::metadata::token::Token;
///
/// let space = AddressSpace::new();
///
/// // Allocate managed objects
/// let str_ref = space.alloc_string("Hello").unwrap();
///
/// // Map raw memory
/// space.map_data(0x1000, &[1, 2, 3, 4], "data").unwrap();
///
/// // Access static fields
/// let field_token = Token::new(0x04000001);
/// space.set_static(field_token, EmValue::I32(42));
/// ```
#[derive(Debug)]
pub struct AddressSpace {
    /// Managed .NET heap (shared across threads).
    heap: SharedHeap,

    /// Memory regions (PE images, mapped data, etc.).
    regions: RwLock<Vec<MemoryRegion>>,

    /// Static field storage.
    statics: StaticFieldStorage,

    /// Next available address for automatic mapping.
    next_address: AtomicU64,

    /// Address space size limit.
    size: u64,

    /// Protection overrides for VirtualProtect emulation.
    ///
    /// Maps page-aligned addresses to their current protection flags.
    /// This allows VirtualProtect to change protection dynamically,
    /// overriding the default protection derived from PE sections.
    ///
    /// Uses `imbl::HashMap` for O(1) fork via structural sharing.
    protection_overrides: RwLock<ImHashMap<u64, MemoryProtection>>,
}

impl AddressSpace {
    /// Page size for protection tracking (4KB).
    const PAGE_SIZE: u64 = 0x1000;

    /// Creates a new address space with default settings.
    ///
    /// Default configuration:
    /// - 64 MB managed heap
    /// - 4 GB address space
    /// - Automatic allocations start at 256 MB
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(64 * 1024 * 1024, 0x1_0000_0000) // 64MB heap, 4GB address space
    }

    /// Creates a new address space with custom configuration.
    ///
    /// # Arguments
    ///
    /// * `heap_size` - Maximum size of the managed heap in bytes
    /// * `address_space_size` - Total address space size in bytes
    #[must_use]
    pub fn with_config(heap_size: usize, address_space_size: u64) -> Self {
        Self {
            heap: SharedHeap::new(heap_size),
            regions: RwLock::new(Vec::new()),
            statics: StaticFieldStorage::new(),
            next_address: AtomicU64::new(0x1000_0000), // Start at 256MB
            size: address_space_size,
            protection_overrides: RwLock::new(ImHashMap::new()),
        }
    }

    /// Creates an address space with an existing shared heap.
    ///
    /// This allows multiple address spaces to share the same managed heap,
    /// useful for emulating multi-threaded scenarios where all threads
    /// share the same GC heap.
    ///
    /// # Arguments
    ///
    /// * `heap` - The shared heap to use
    #[must_use]
    pub fn with_heap(heap: SharedHeap) -> Self {
        Self {
            heap,
            regions: RwLock::new(Vec::new()),
            statics: StaticFieldStorage::new(),
            next_address: AtomicU64::new(0x1000_0000),
            size: 0x1_0000_0000,
            protection_overrides: RwLock::new(ImHashMap::new()),
        }
    }

    /// Returns a reference to the shared heap.
    #[must_use]
    pub fn heap(&self) -> &SharedHeap {
        &self.heap
    }

    /// Returns a reference to the underlying [`ManagedHeap`].
    #[must_use]
    pub fn managed_heap(&self) -> &ManagedHeap {
        self.heap.heap()
    }

    /// Returns a reference to the static field storage.
    #[must_use]
    pub fn statics(&self) -> &StaticFieldStorage {
        &self.statics
    }

    /// Maps a region into the address space at a specific address.
    ///
    /// # Arguments
    ///
    /// * `address` - The base address to map the region at
    /// * `region` - The memory region to map
    ///
    /// # Errors
    ///
    /// Returns an error if the region overlaps with an existing mapping or
    /// if the region lock is poisoned.
    pub fn map_at(&self, address: u64, region: MemoryRegion) -> Result<()> {
        let mut regions = self.regions.write().map_err(|_| {
            Error::from(EmulationError::InternalError {
                description: "region lock poisoned".to_string(),
            })
        })?;

        // Check for overlaps
        for existing in regions.iter() {
            if Self::regions_overlap(existing, &region) {
                return Err(EmulationError::InvalidAddress {
                    address,
                    reason: "region overlaps with existing mapping".to_string(),
                }
                .into());
            }
        }

        regions.push(region);
        Ok(())
    }

    /// Maps a region at an automatically chosen address.
    ///
    /// The address is selected from the available address space and aligned
    /// to a page boundary (4KB). The region's base address is updated to
    /// reflect the chosen location.
    ///
    /// # Arguments
    ///
    /// * `region` - The memory region to map (base address will be updated)
    ///
    /// # Returns
    ///
    /// The base address where the region was mapped.
    ///
    /// # Errors
    ///
    /// Returns an error if the mapping fails.
    pub fn map(&self, region: MemoryRegion) -> Result<u64> {
        let size = region.size();
        let aligned_size = (size + 0xFFF) & !0xFFF; // Page align

        // Find next available address
        let base = self
            .next_address
            .fetch_add(aligned_size as u64, Ordering::SeqCst);

        // PE images should use map_at with explicit base
        if region.is_pe_image() {
            return Err(EmulationError::InternalError {
                description: "PE images must use map_at with explicit base address".to_string(),
            }
            .into());
        }

        // Update region base
        let region = region.with_base(base);

        self.map_at(base, region)?;
        Ok(base)
    }

    /// Unmaps a region by its base address.
    ///
    /// # Arguments
    ///
    /// * `base` - The base address of the region to unmap
    ///
    /// # Errors
    ///
    /// Returns an error if no region exists at the given address.
    pub fn unmap(&self, base: u64) -> Result<()> {
        let mut regions = self.regions.write().map_err(|_| {
            Error::from(EmulationError::InternalError {
                description: "region lock poisoned".to_string(),
            })
        })?;

        if let Some(pos) = regions.iter().position(|r| r.base() == base) {
            regions.remove(pos);
            Ok(())
        } else {
            Err(EmulationError::InvalidAddress {
                address: base,
                reason: "no region at this address".to_string(),
            }
            .into())
        }
    }

    /// Reads bytes from any mapped region.
    ///
    /// # Arguments
    ///
    /// * `address` - The address to read from
    /// * `len` - The number of bytes to read
    ///
    /// # Errors
    ///
    /// Returns an error if the address is not mapped or the read fails.
    pub fn read(&self, address: u64, len: usize) -> Result<Vec<u8>> {
        let regions = self.regions.read().map_err(|_| {
            Error::from(EmulationError::InternalError {
                description: "region lock poisoned".to_string(),
            })
        })?;

        for region in regions.iter() {
            if region.contains_range(address, len) {
                return region.read(address, len).ok_or_else(|| {
                    EmulationError::InvalidAddress {
                        address,
                        reason: "read failed".to_string(),
                    }
                    .into()
                });
            }
        }

        Err(EmulationError::InvalidAddress {
            address,
            reason: "address not mapped".to_string(),
        }
        .into())
    }

    /// Writes bytes to any mapped region.
    ///
    /// # Arguments
    ///
    /// * `address` - The address to write to
    /// * `data` - The bytes to write
    ///
    /// # Errors
    ///
    /// Returns an error if the address is not mapped, the region is read-only,
    /// or the write otherwise fails.
    pub fn write(&self, address: u64, data: &[u8]) -> Result<()> {
        let regions = self.regions.read().map_err(|_| {
            Error::from(EmulationError::InternalError {
                description: "region lock poisoned".to_string(),
            })
        })?;

        for region in regions.iter() {
            if region.contains_range(address, data.len()) {
                if region.write(address, data) {
                    return Ok(());
                }
                return Err(EmulationError::InvalidAddress {
                    address,
                    reason: "write failed (possibly read-only)".to_string(),
                }
                .into());
            }
        }

        Err(EmulationError::InvalidAddress {
            address,
            reason: "address not mapped".to_string(),
        }
        .into())
    }

    /// Returns `true` if the address is within a mapped region.
    ///
    /// # Arguments
    ///
    /// * `address` - The address to check
    #[must_use]
    pub fn is_valid(&self, address: u64) -> bool {
        let Ok(regions) = self.regions.read() else {
            return false;
        };
        regions.iter().any(|r| r.contains(address))
    }

    /// Returns the region containing the given address, if any.
    ///
    /// # Arguments
    ///
    /// * `address` - The address to look up
    #[must_use]
    pub fn get_region(&self, address: u64) -> Option<MemoryRegion> {
        let regions = self.regions.read().ok()?;
        regions.iter().find(|r| r.contains(address)).cloned()
    }

    /// Returns the memory protection flags for an address.
    ///
    /// This method first checks for any runtime protection overrides (set by
    /// `VirtualProtect` emulation), then falls back to the region's default
    /// protection. For PE images, the default considers the section containing
    /// the address.
    ///
    /// # Arguments
    ///
    /// * `address` - The address to check
    #[must_use]
    pub fn get_protection(&self, address: u64) -> Option<MemoryProtection> {
        // Check for override first (page-aligned)
        let page_addr = address & !(Self::PAGE_SIZE - 1);
        if let Ok(overrides) = self.protection_overrides.read() {
            if let Some(&prot) = overrides.get(&page_addr) {
                return Some(prot);
            }
        }

        // Fall back to region's inherent protection
        let regions = self.regions.read().ok()?;
        regions
            .iter()
            .find(|r| r.contains(address))
            .map(|r| r.protection_at(address))
    }

    /// Sets the memory protection for a range of addresses.
    ///
    /// This emulates `VirtualProtect` by storing protection overrides at
    /// page granularity. The original protection for the first page is returned.
    ///
    /// # Arguments
    ///
    /// * `address` - The starting address (will be page-aligned)
    /// * `size` - The size of the region to protect
    /// * `new_protection` - The new protection flags
    ///
    /// # Returns
    ///
    /// The previous protection of the first affected page, or `None` if the
    /// address is not mapped.
    pub fn set_protection(
        &self,
        address: u64,
        size: usize,
        new_protection: MemoryProtection,
    ) -> Option<MemoryProtection> {
        // Calculate page-aligned range
        let start_page = address & !(Self::PAGE_SIZE - 1);

        // Anti-emulation countermeasure:
        //
        // Some obfuscators (notably ConfuserEx) mark their encrypted sections as RWX
        // in the PE headers, then check VirtualProtect's returned old protection:
        //
        //   uint w = 0x40;  // PAGE_EXECUTE_READWRITE
        //   VirtualProtect(addr, size, w, out w);
        //   if (w == 0x40) return;  // Skip decryption if already RWX
        //
        // A naive emulator that accurately maps PE section characteristics would
        // return 0x40, causing decryption to be skipped. Real Windows apparently
        // behaves differently (possibly due to copy-on-write, DEP, or CLR-specific
        // loading behavior), returning a different value on first access.
        //
        // We handle this by returning READ_EXECUTE (0x20) for the FIRST VirtualProtect
        // call on executable sections, regardless of PE characteristics. Subsequent
        // calls return the actual stored protection, preserving re-entry guards.
        let old_protection = if let Ok(overrides) = self.protection_overrides.read() {
            if overrides.contains_key(&start_page) {
                // Has override - use it
                drop(overrides);
                self.get_protection(address)?
            } else {
                // No override yet - this is the first call.
                // Return READ_EXECUTE for executable sections to simulate
                // fresh process state (before any VirtualProtect calls).
                drop(overrides);
                let region_prot = self.get_protection(address)?;
                if region_prot.contains(MemoryProtection::EXECUTE) {
                    MemoryProtection::READ_EXECUTE
                } else {
                    region_prot
                }
            }
        } else {
            self.get_protection(address)?
        };

        // Calculate end page
        let end_addr = address.saturating_add(size as u64);
        let end_page = (end_addr + Self::PAGE_SIZE - 1) & !(Self::PAGE_SIZE - 1);

        // Update protection for all affected pages
        if let Ok(mut overrides) = self.protection_overrides.write() {
            let mut page = start_page;
            while page < end_page {
                overrides.insert(page, new_protection);
                page += Self::PAGE_SIZE;
            }
        }

        Some(old_protection)
    }

    /// Gets a static field value.
    ///
    /// # Arguments
    ///
    /// * `field_token` - The metadata token of the static field
    #[must_use]
    pub fn get_static(&self, field_token: Token) -> Option<EmValue> {
        self.statics.get(field_token)
    }

    /// Sets a static field value.
    ///
    /// # Arguments
    ///
    /// * `field_token` - The metadata token of the static field
    /// * `value` - The value to store
    pub fn set_static(&self, field_token: Token, value: EmValue) {
        self.statics.set(field_token, value);
    }

    /// Allocates unmanaged memory (for `Marshal.AllocHGlobal`, etc.).
    ///
    /// The memory is zeroed and mapped at an automatically chosen address.
    ///
    /// # Arguments
    ///
    /// * `size` - The size of the allocation in bytes
    ///
    /// # Returns
    ///
    /// The base address of the allocated region.
    ///
    /// # Errors
    ///
    /// Returns an error if the mapping fails.
    pub fn alloc_unmanaged(&self, size: usize) -> Result<u64> {
        let region = MemoryRegion::unmanaged_alloc(0, size);
        self.map(region)
    }

    /// Frees unmanaged memory previously allocated with [`alloc_unmanaged`](Self::alloc_unmanaged).
    ///
    /// # Arguments
    ///
    /// * `address` - The base address of the allocation to free
    ///
    /// # Errors
    ///
    /// Returns an error if the address does not correspond to an unmanaged allocation.
    pub fn free_unmanaged(&self, address: u64) -> Result<()> {
        // Verify it's an unmanaged allocation
        let regions = self.regions.read().map_err(|_| {
            Error::from(EmulationError::InternalError {
                description: "region lock poisoned".to_string(),
            })
        })?;

        let is_unmanaged = regions
            .iter()
            .any(|r| r.base() == address && r.is_unmanaged_alloc());

        drop(regions);

        if is_unmanaged {
            self.unmap(address)
        } else {
            Err(EmulationError::InvalidAddress {
                address,
                reason: "not an unmanaged allocation".to_string(),
            }
            .into())
        }
    }

    /// Copies a block of memory from source to destination.
    ///
    /// Implements the CIL `cpblk` instruction semantics. Handles overlapping
    /// regions by reading the source data first.
    ///
    /// # Arguments
    ///
    /// * `dest` - Destination address
    /// * `src` - Source address
    /// * `size` - Number of bytes to copy
    ///
    /// # Errors
    ///
    /// Returns an error if either address is unmapped or the copy fails.
    pub fn copy_block(&self, dest: u64, src: u64, size: usize) -> Result<()> {
        if size == 0 {
            return Ok(());
        }

        // Read source data
        let src_data = self.read(src, size)?;

        // Write to destination
        self.write(dest, &src_data)
    }

    /// Initializes a block of memory with a byte value.
    ///
    /// Implements the CIL `initblk` instruction semantics.
    ///
    /// # Arguments
    ///
    /// * `address` - The starting address to initialize
    /// * `value` - The byte value to fill with
    /// * `size` - Number of bytes to initialize
    ///
    /// # Errors
    ///
    /// Returns an error if the address is unmapped.
    pub fn init_block(&self, address: u64, value: u8, size: usize) -> Result<()> {
        if size == 0 {
            return Ok(());
        }

        let data = vec![value; size];
        self.write(address, &data)
    }

    /// Maps a PE image at its preferred base address.
    ///
    /// # Arguments
    ///
    /// * `data` - The PE image bytes (should be mapped according to section alignment)
    /// * `preferred_base` - The preferred base address (usually from the PE header)
    /// * `sections` - Section information for protection lookup
    /// * `name` - A label for the image (for debugging)
    ///
    /// # Returns
    ///
    /// The base address where the image was mapped (same as `preferred_base`).
    ///
    /// # Errors
    ///
    /// Returns an error if the mapping fails.
    pub fn map_pe_image(
        &self,
        data: &[u8],
        preferred_base: u64,
        sections: Vec<SectionInfo>,
        name: impl Into<String>,
    ) -> Result<u64> {
        let region = MemoryRegion::pe_image(preferred_base, data, sections, name);
        self.map_at(preferred_base, region)?;
        Ok(preferred_base)
    }

    /// Maps raw data at a specific address with read-write protection.
    ///
    /// # Arguments
    ///
    /// * `address` - The address to map the data at
    /// * `data` - The data bytes
    /// * `label` - A label for the region (for debugging)
    ///
    /// # Errors
    ///
    /// Returns an error if the mapping fails.
    pub fn map_data(&self, address: u64, data: &[u8], label: impl Into<String>) -> Result<()> {
        let region = MemoryRegion::mapped_data(address, data, label, MemoryProtection::READ_WRITE);
        self.map_at(address, region)
    }

    /// Returns information about all mapped regions.
    ///
    /// Each tuple contains `(base_address, size, label)`.
    #[must_use]
    pub fn regions(&self) -> Vec<(u64, usize, String)> {
        match self.regions.read() {
            Ok(regions) => regions
                .iter()
                .map(|r| (r.base(), r.size(), r.label().to_string()))
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Returns the total size of all mapped regions in bytes.
    #[must_use]
    pub fn mapped_size(&self) -> usize {
        match self.regions.read() {
            Ok(regions) => regions.iter().map(MemoryRegion::size).sum(),
            Err(_) => 0,
        }
    }

    /// Checks if two regions overlap in the address space.
    ///
    /// Uses the standard interval overlap test: two intervals [a_start, a_end)
    /// and [b_start, b_end) overlap iff a_start < b_end && b_start < a_end.
    fn regions_overlap(a: &MemoryRegion, b: &MemoryRegion) -> bool {
        let a_start = a.base();
        let a_end = a.end();
        let b_start = b.base();
        let b_end = b.end();

        a_start < b_end && b_start < a_end
    }

    /// Allocates a string on the managed heap.
    ///
    /// # Arguments
    ///
    /// * `value` - The string value to allocate
    ///
    /// # Errors
    ///
    /// Returns an error if the heap is out of memory.
    pub fn alloc_string(&self, value: &str) -> Result<HeapRef> {
        self.heap.alloc_string(value)
    }

    /// Gets a string from the managed heap.
    ///
    /// # Arguments
    ///
    /// * `heap_ref` - Reference to the string object
    ///
    /// # Returns
    ///
    /// An `Arc<str>` for efficient, borrow-free access.
    ///
    /// # Errors
    ///
    /// Returns an error if the reference is invalid or not a string.
    pub fn get_string(&self, heap_ref: HeapRef) -> Result<std::sync::Arc<str>> {
        self.heap.get_string(heap_ref)
    }

    /// Allocates an empty object on the managed heap.
    ///
    /// # Arguments
    ///
    /// * `type_token` - The type token for the object
    ///
    /// # Errors
    ///
    /// Returns an error if the heap is out of memory.
    pub fn alloc_object(&self, type_token: Token) -> Result<HeapRef> {
        self.heap.alloc_object(type_token)
    }

    /// Gets a field value from a heap object.
    ///
    /// # Arguments
    ///
    /// * `heap_ref` - Reference to the object
    /// * `field_token` - Token of the field to read
    ///
    /// # Errors
    ///
    /// Returns an error if the reference is invalid, not an object,
    /// or the field does not exist.
    pub fn get_field(&self, heap_ref: HeapRef, field_token: Token) -> Result<EmValue> {
        self.heap.get_field(heap_ref, field_token)
    }

    /// Sets a field value on a heap object.
    ///
    /// # Arguments
    ///
    /// * `heap_ref` - Reference to the object
    /// * `field_token` - Token of the field to set
    /// * `value` - The value to store
    ///
    /// # Errors
    ///
    /// Returns an error if the reference is invalid or not an object.
    pub fn set_field(&self, heap_ref: HeapRef, field_token: Token, value: EmValue) -> Result<()> {
        self.heap.set_field(heap_ref, field_token, value)
    }
}

impl Default for AddressSpace {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for AddressSpace {
    fn clone(&self) -> Self {
        // Clone shares the heap (cheap Arc clone) but copies regions
        let regions = match self.regions.read() {
            Ok(r) => r.clone(),
            Err(_) => Vec::new(),
        };

        let protection_overrides = match self.protection_overrides.read() {
            Ok(p) => p.clone(), // O(1) due to imbl structural sharing
            Err(_) => ImHashMap::new(),
        };

        Self {
            heap: self.heap.clone(), // Cheap Arc clone
            regions: RwLock::new(regions),
            statics: self.statics.clone(),
            next_address: AtomicU64::new(self.next_address.load(Ordering::SeqCst)),
            size: self.size,
            protection_overrides: RwLock::new(protection_overrides),
        }
    }
}

impl AddressSpace {
    /// Creates a fresh address space that shares memory regions but has independent mutable state.
    ///
    /// This is optimized for spawning lightweight emulation instances from a template:
    /// - **Shared (cheap)**: Memory regions (PE images, mapped data) - data uses `Arc` internally
    /// - **Fresh**: Heap, static fields, protection overrides, allocation pointer
    ///
    /// This pattern is ideal for deobfuscation where you need to run the same decryptor
    /// method many times with different arguments. The expensive PE loading and mapping
    /// is done once in the template, while each spawn gets fresh mutable state.
    ///
    /// # Example
    ///
    /// ```rust
    /// use dotscope::emulation::AddressSpace;
    ///
    /// // Create template with mapped data
    /// let template = AddressSpace::new();
    /// template.map_data(0x10000, &[1, 2, 3, 4], "data").unwrap();
    ///
    /// // Spawn a fresh instance - shares regions, fresh heap/statics
    /// let fresh = template.spawn_fresh();
    ///
    /// // Modifications to fresh don't affect template's heap/statics
    /// fresh.set_static(dotscope::metadata::token::Token::new(0x04000001),
    ///                  dotscope::emulation::EmValue::I32(42));
    /// assert!(template.get_static(dotscope::metadata::token::Token::new(0x04000001)).is_none());
    /// ```
    #[must_use]
    pub fn spawn_fresh(&self) -> Self {
        // Clone regions - this is cheap because pages use CoW internally
        let regions = match self.regions.read() {
            Ok(r) => r.clone(),
            Err(_) => Vec::new(),
        };

        Self {
            // Fresh heap - each spawn gets independent heap allocations
            heap: SharedHeap::default(),
            // Shared regions - cheap clone due to CoW pages
            regions: RwLock::new(regions),
            // Fresh statics - each spawn starts with empty static field storage
            statics: StaticFieldStorage::new(),
            // Fresh allocation pointer
            next_address: AtomicU64::new(self.next_address.load(Ordering::SeqCst)),
            // Same size limit
            size: self.size,
            // Fresh protection overrides (VirtualProtect state)
            protection_overrides: RwLock::new(ImHashMap::new()),
        }
    }

    /// Forks this address space with full Copy-on-Write semantics.
    ///
    /// Creates an independent copy that shares data with the original via
    /// structural sharing. Both the original and fork can be modified independently -
    /// only the modified data is actually copied (true copy-on-write).
    ///
    /// # What Gets Forked
    ///
    /// - **Memory regions**: Forked with per-page CoW (4KB granularity)
    /// - **Managed heap**: Forked via `imbl` structural sharing (O(1))
    /// - **Static fields**: Forked via `imbl` structural sharing (O(1))
    /// - **Protection overrides**: Forked via `imbl` structural sharing (O(1))
    ///
    /// # Performance
    ///
    /// This is an O(1) operation for heap, statics, and protection overrides.
    /// Regions are O(n) where n is the number of regions (not pages), since
    /// each region's pages use CoW internally.
    ///
    /// # Use Case
    ///
    /// Ideal for running many parallel decryption operations from a single
    /// setup. The expensive emulator initialization (PE loading, type resolution,
    /// static initializers) happens once, then `fork()` creates lightweight
    /// copies for each decryptor call.
    ///
    /// # Example
    ///
    /// ```rust
    /// use dotscope::emulation::{AddressSpace, EmValue};
    /// use dotscope::metadata::token::Token;
    ///
    /// // Set up template with data
    /// let template = AddressSpace::new();
    /// template.map_data(0x1000, &[1, 2, 3, 4], "data").unwrap();
    /// template.set_static(Token::new(0x04000001), EmValue::I32(42));
    ///
    /// // Fork creates independent copy with shared backing
    /// let forked = template.fork();
    ///
    /// // Modifications are independent
    /// forked.set_static(Token::new(0x04000001), EmValue::I32(100));
    /// forked.write(0x1000, &[0xFF]).unwrap();
    ///
    /// // Original unchanged
    /// assert_eq!(template.get_static(Token::new(0x04000001)), Some(EmValue::I32(42)));
    /// assert_eq!(template.read(0x1000, 1).unwrap(), vec![1]);
    /// ```
    #[must_use]
    pub fn fork(&self) -> Self {
        // Fork all regions (each region forks its pages)
        let regions = match self.regions.read() {
            Ok(r) => r.iter().filter_map(|region| region.fork().ok()).collect(),
            Err(_) => Vec::new(),
        };

        // Fork protection overrides (O(1) due to imbl)
        let protection_overrides = match self.protection_overrides.read() {
            Ok(p) => p.clone(),
            Err(_) => ImHashMap::new(),
        };

        Self {
            // Fork heap - O(1) due to imbl structural sharing
            heap: self.heap.fork(),
            // Forked regions - each region's pages use CoW
            regions: RwLock::new(regions),
            // Fork statics - O(1) due to imbl structural sharing
            statics: self.statics.fork(),
            // Copy allocation pointer
            next_address: AtomicU64::new(self.next_address.load(Ordering::SeqCst)),
            // Same size limit
            size: self.size,
            // Fork protection overrides - O(1) due to imbl
            protection_overrides: RwLock::new(protection_overrides),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        emulation::{
            memory::{
                addressspace::{AddressSpace, SharedHeap},
                region::MemoryProtection,
            },
            EmValue,
        },
        metadata::token::Token,
    };

    #[test]
    fn test_address_space_creation() {
        let space = AddressSpace::new();
        assert!(space.regions().is_empty());
    }

    #[test]
    fn test_map_and_read_data() {
        let space = AddressSpace::new();
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];

        space.map_data(0x1000, &data, "test").unwrap();

        let read = space.read(0x1000, 4).unwrap();
        assert_eq!(read, data);
    }

    #[test]
    fn test_write_data() {
        let space = AddressSpace::new();
        space.map_data(0x1000, &[0u8; 16], "test").unwrap();

        space.write(0x1000, &[0xCA, 0xFE]).unwrap();

        let read = space.read(0x1000, 2).unwrap();
        assert_eq!(read, vec![0xCA, 0xFE]);
    }

    #[test]
    fn test_static_fields() {
        let space = AddressSpace::new();
        let field = Token::new(0x04000001);

        assert!(space.get_static(field).is_none());

        space.set_static(field, EmValue::I32(42));
        assert_eq!(space.get_static(field), Some(EmValue::I32(42)));
    }

    #[test]
    fn test_shared_heap() {
        let space1 = AddressSpace::new();
        let str_ref = space1.alloc_string("Hello").unwrap();

        // Clone shares the heap
        let space2 = space1.clone();

        // Both can see the string
        let s1 = space1.get_string(str_ref).unwrap();
        let s2 = space2.get_string(str_ref).unwrap();
        assert_eq!(&*s1, "Hello");
        assert_eq!(&*s2, "Hello");

        // Allocating in one is visible in the other
        let str_ref2 = space2.alloc_string("World").unwrap();
        let s3 = space1.get_string(str_ref2).unwrap();
        assert_eq!(&*s3, "World");
    }

    #[test]
    fn test_unmanaged_alloc() {
        let space = AddressSpace::new();

        let addr = space.alloc_unmanaged(256).unwrap();
        assert!(space.is_valid(addr));

        // Write and read
        space.write(addr, &[1, 2, 3, 4]).unwrap();
        let data = space.read(addr, 4).unwrap();
        assert_eq!(data, vec![1, 2, 3, 4]);

        // Free
        space.free_unmanaged(addr).unwrap();
        assert!(!space.is_valid(addr));
    }

    #[test]
    fn test_heap_delegation() {
        let space = AddressSpace::new();

        // Test string allocation through AddressSpace
        let str_ref = space.alloc_string("Test").unwrap();
        let s = space.get_string(str_ref).unwrap();
        assert_eq!(&*s, "Test");

        // Test object allocation through AddressSpace
        let type_token = Token::new(0x02000001);
        let field_token = Token::new(0x04000001);
        let obj_ref = space.alloc_object(type_token).unwrap();

        space
            .set_field(obj_ref, field_token, EmValue::I32(100))
            .unwrap();
        let value = space.get_field(obj_ref, field_token).unwrap();
        assert_eq!(value, EmValue::I32(100));
    }

    #[test]
    fn test_fork_memory_isolation() {
        let space = AddressSpace::new();
        space.map_data(0x1000, &[1, 2, 3, 4], "test").unwrap();

        // Fork
        let forked = space.fork();

        // Both see the same initial data
        assert_eq!(space.read(0x1000, 4).unwrap(), vec![1, 2, 3, 4]);
        assert_eq!(forked.read(0x1000, 4).unwrap(), vec![1, 2, 3, 4]);

        // Modify forked
        forked.write(0x1000, &[0xFF, 0xFE]).unwrap();

        // Original unchanged, fork modified
        assert_eq!(space.read(0x1000, 4).unwrap(), vec![1, 2, 3, 4]);
        assert_eq!(forked.read(0x1000, 4).unwrap(), vec![0xFF, 0xFE, 3, 4]);
    }

    #[test]
    fn test_fork_heap_isolation() {
        let space = AddressSpace::new();
        let str_ref = space.alloc_string("Original").unwrap();

        // Fork
        let forked = space.fork();

        // Both see the same string
        assert_eq!(&*space.get_string(str_ref).unwrap(), "Original");
        assert_eq!(&*forked.get_string(str_ref).unwrap(), "Original");

        // Allocate new string in fork
        let new_ref = forked.alloc_string("Forked").unwrap();
        assert_eq!(&*forked.get_string(new_ref).unwrap(), "Forked");

        // Original doesn't see the new string
        assert!(space.get_string(new_ref).is_err());
    }

    #[test]
    fn test_fork_statics_isolation() {
        let space = AddressSpace::new();
        let field = Token::new(0x04000001);
        space.set_static(field, EmValue::I32(42));

        // Fork
        let forked = space.fork();

        // Both see the same static
        assert_eq!(space.get_static(field), Some(EmValue::I32(42)));
        assert_eq!(forked.get_static(field), Some(EmValue::I32(42)));

        // Modify in fork
        forked.set_static(field, EmValue::I32(100));

        // Original unchanged
        assert_eq!(space.get_static(field), Some(EmValue::I32(42)));
        assert_eq!(forked.get_static(field), Some(EmValue::I32(100)));
    }

    #[test]
    fn test_fork_protection_isolation() {
        let space = AddressSpace::new();
        space.map_data(0x1000, &vec![0u8; 0x2000], "test").unwrap();

        // Set protection
        space.set_protection(0x1000, 0x1000, MemoryProtection::READ_EXECUTE);

        // Fork
        let forked = space.fork();

        // Both see the same protection
        assert_eq!(
            space.get_protection(0x1000),
            Some(MemoryProtection::READ_EXECUTE)
        );
        assert_eq!(
            forked.get_protection(0x1000),
            Some(MemoryProtection::READ_EXECUTE)
        );

        // Modify in fork
        forked.set_protection(0x1000, 0x1000, MemoryProtection::READ_WRITE);

        // Original unchanged
        assert_eq!(
            space.get_protection(0x1000),
            Some(MemoryProtection::READ_EXECUTE)
        );
        assert_eq!(
            forked.get_protection(0x1000),
            Some(MemoryProtection::READ_WRITE)
        );
    }

    #[test]
    fn test_multiple_forks_isolation() {
        let space = AddressSpace::new();
        let field = Token::new(0x04000001);
        space.set_static(field, EmValue::I32(1));

        // Create multiple forks
        let fork1 = space.fork();
        let fork2 = space.fork();

        // Modify each independently
        fork1.set_static(field, EmValue::I32(10));
        fork2.set_static(field, EmValue::I32(20));

        // Each has its own value
        assert_eq!(space.get_static(field), Some(EmValue::I32(1)));
        assert_eq!(fork1.get_static(field), Some(EmValue::I32(10)));
        assert_eq!(fork2.get_static(field), Some(EmValue::I32(20)));
    }

    #[test]
    fn test_shared_heap_fork() {
        let heap = SharedHeap::new(1024 * 1024);
        let str_ref = heap.alloc_string("Hello").unwrap();

        // Fork the heap
        let forked = heap.fork();

        // Both see the string
        assert_eq!(&*heap.get_string(str_ref).unwrap(), "Hello");
        assert_eq!(&*forked.get_string(str_ref).unwrap(), "Hello");

        // Allocate in forked
        let new_ref = forked.alloc_string("World").unwrap();
        assert_eq!(&*forked.get_string(new_ref).unwrap(), "World");

        // Original doesn't see it
        assert!(heap.get_string(new_ref).is_err());
    }
}
