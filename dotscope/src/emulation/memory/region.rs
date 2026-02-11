//! Memory region types for address space management.
//!
//! This module defines the different types of memory regions that can be
//! mapped into the emulated [`AddressSpace`](super::AddressSpace):
//!
//! - **PE images** - Loaded executables and DLLs with section-aware protection
//! - **Mapped data** - Raw data regions with configurable protection
//! - **Unmanaged allocations** - Heap allocations from `Marshal.AllocHGlobal`, etc.
//!
//! # Copy-on-Write Semantics
//!
//! All memory regions use page-based copy-on-write. Each region is divided into
//! 4KB pages, and writes only copy the specific page being modified. This enables
//! efficient `fork()` operations where parent and child share unmodified pages.
//!
//! # Memory Protection
//!
//! Regions have associated [`MemoryProtection`] flags that control read, write,
//! and execute permissions. For PE images, protection is determined per-section
//! based on the PE section characteristics.
//!
//! # Thread Safety
//!
//! All operations use interior mutability via per-page `RwLock`. Multiple readers
//! can access different pages concurrently, and writes only lock the affected page.

use std::sync::{Arc, RwLock};

use bitflags::bitflags;

use crate::emulation::{
    engine::EmulationError,
    memory::page::{Page, PAGE_SIZE},
};

/// Unique identifier for a thread in the emulated process.
///
/// Thread IDs are used to associate stack regions with their owning thread
/// and to track per-thread state during multi-threaded emulation.
///
/// # Main Thread
///
/// The main thread is always assigned ID 0 via [`ThreadId::MAIN`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ThreadId(pub u32);

impl ThreadId {
    /// The main thread ID (always 0).
    pub const MAIN: ThreadId = ThreadId(0);

    /// Creates a new thread ID with the given value.
    ///
    /// # Arguments
    ///
    /// * `id` - The numeric thread identifier
    #[must_use]
    pub fn new(id: u32) -> Self {
        Self(id)
    }

    /// Returns the raw numeric ID value.
    #[must_use]
    pub fn value(&self) -> u32 {
        self.0
    }
}

impl Default for ThreadId {
    fn default() -> Self {
        Self::MAIN
    }
}

impl std::fmt::Display for ThreadId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Thread({})", self.0)
    }
}

bitflags! {
    /// Memory protection flags for address space regions.
    ///
    /// These flags control what operations are permitted on a memory region.
    /// They are modeled after Windows `PAGE_*` protection constants and are
    /// derived from PE section characteristics for PE image regions.
    ///
    /// # Common Combinations
    ///
    /// - [`READ_WRITE`](Self::READ_WRITE) - Data sections (`.data`, `.bss`)
    /// - [`READ_EXECUTE`](Self::READ_EXECUTE) - Code sections (`.text`)
    /// - [`READ`](Self::READ) - Read-only sections (`.rdata`)
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct MemoryProtection: u32 {
        /// Region is readable.
        const READ = 0x01;
        /// Region is writable.
        const WRITE = 0x02;
        /// Region is executable.
        const EXECUTE = 0x04;
        /// Region is a guard page (triggers exception on access).
        const GUARD = 0x100;
        /// Read and write access (common for data sections).
        const READ_WRITE = Self::READ.bits() | Self::WRITE.bits();
        /// Read, write, and execute access.
        const READ_WRITE_EXECUTE = Self::READ.bits() | Self::WRITE.bits() | Self::EXECUTE.bits();
        /// Read and execute access (common for code sections).
        const READ_EXECUTE = Self::READ.bits() | Self::EXECUTE.bits();
    }
}

impl Default for MemoryProtection {
    fn default() -> Self {
        Self::READ_WRITE
    }
}

impl MemoryProtection {
    /// Windows PAGE_* protection constants.
    const PAGE_NOACCESS: u32 = 0x01;
    const PAGE_READONLY: u32 = 0x02;
    const PAGE_READWRITE: u32 = 0x04;
    const PAGE_WRITECOPY: u32 = 0x08;
    const PAGE_EXECUTE: u32 = 0x10;
    const PAGE_EXECUTE_READ: u32 = 0x20;
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;

    /// Converts a Windows PAGE_* protection constant to `MemoryProtection` flags.
    ///
    /// # Arguments
    ///
    /// * `page_protect` - A Windows PAGE_* constant (e.g., 0x20 for PAGE_EXECUTE_READ)
    ///
    /// # Returns
    ///
    /// The equivalent `MemoryProtection` flags.
    #[must_use]
    pub fn from_windows(page_protect: u32) -> Self {
        match page_protect & 0xFF {
            Self::PAGE_NOACCESS => Self::empty(),
            Self::PAGE_READONLY => Self::READ,
            Self::PAGE_EXECUTE => Self::EXECUTE,
            Self::PAGE_EXECUTE_READ => Self::READ_EXECUTE,
            Self::PAGE_EXECUTE_READWRITE | Self::PAGE_EXECUTE_WRITECOPY => Self::READ_WRITE_EXECUTE,
            // Default: READWRITE, WRITECOPY, and other unknown values
            _ => Self::READ_WRITE,
        }
    }

    /// Converts `MemoryProtection` flags to a Windows PAGE_* constant.
    ///
    /// # Returns
    ///
    /// The equivalent Windows PAGE_* constant.
    #[must_use]
    pub fn to_windows(self) -> u32 {
        let r = self.contains(Self::READ);
        let w = self.contains(Self::WRITE);
        let x = self.contains(Self::EXECUTE);

        match (r, w, x) {
            (false, false, false) => Self::PAGE_NOACCESS,
            (true, false, false) => Self::PAGE_READONLY,
            // READWRITE for both (r,w,!x) and unusual (!r,w,!x)
            (_, true, false) => Self::PAGE_READWRITE,
            (false, false, true) => Self::PAGE_EXECUTE,
            (true, false, true) => Self::PAGE_EXECUTE_READ,
            // EXECUTE_READWRITE for both (r,w,x) and unusual (!r,w,x)
            (_, true, true) => Self::PAGE_EXECUTE_READWRITE,
        }
    }
}

/// Information about a PE section within a loaded image.
///
/// This structure contains the metadata needed to map a PE section and
/// determine its memory protection. It is used by [`MemoryRegion`]
/// to provide per-section protection lookup.
#[derive(Clone, Debug)]
pub struct SectionInfo {
    /// Section name (e.g., ".text", ".data", ".rdata").
    pub name: String,
    /// Virtual address (RVA) relative to the image base.
    pub virtual_address: u32,
    /// Virtual size of the section in memory.
    pub virtual_size: u32,
    /// File offset to the raw section data.
    pub raw_data_offset: u32,
    /// Size of raw data in the file (may differ from virtual size).
    pub raw_data_size: u32,
    /// PE section characteristics flags (from `IMAGE_SECTION_HEADER`).
    pub characteristics: u32,
    /// Protection flags derived from the characteristics.
    pub protection: MemoryProtection,
}

impl SectionInfo {
    /// Creates section info from raw PE section data.
    ///
    /// The protection flags are automatically derived from the PE
    /// characteristics using the standard `IMAGE_SCN_MEM_*` flags.
    ///
    /// # Arguments
    ///
    /// * `name` - Section name (e.g., ".text")
    /// * `virtual_address` - RVA of the section
    /// * `virtual_size` - Size in memory
    /// * `raw_data_offset` - File offset to data
    /// * `raw_data_size` - Size of data in file
    /// * `characteristics` - PE section characteristics
    #[must_use]
    pub fn new(
        name: String,
        virtual_address: u32,
        virtual_size: u32,
        raw_data_offset: u32,
        raw_data_size: u32,
        characteristics: u32,
    ) -> Self {
        // Derive protection from PE characteristics
        let mut protection = MemoryProtection::empty();

        // IMAGE_SCN_MEM_READ = 0x40000000
        if characteristics & 0x4000_0000 != 0 {
            protection |= MemoryProtection::READ;
        }
        // IMAGE_SCN_MEM_WRITE = 0x80000000
        if characteristics & 0x8000_0000 != 0 {
            protection |= MemoryProtection::WRITE;
        }
        // IMAGE_SCN_MEM_EXECUTE = 0x20000000
        if characteristics & 0x2000_0000 != 0 {
            protection |= MemoryProtection::EXECUTE;
        }

        Self {
            name,
            virtual_address,
            virtual_size,
            raw_data_offset,
            raw_data_size,
            characteristics,
            protection,
        }
    }
}

/// A memory region in the emulated address space.
///
/// Memory regions represent contiguous blocks of memory with associated
/// metadata and protection. They use page-based copy-on-write for efficient
/// forking - unmodified pages are shared between parent and child.
///
/// # Copy-on-Write
///
/// Each region is divided into 4KB pages. When a page is first written,
/// the backing data is copied to a local buffer (CoW). This enables:
///
/// - Efficient `fork()` - child shares parent's unmodified pages
/// - Memory efficiency - only modified pages consume extra memory
/// - Thread safety - each page has its own lock
///
/// # Thread Safety
///
/// All operations take `&self` and use interior mutability. Multiple threads
/// can read from different pages concurrently. Writes to a page acquire that
/// page's write lock and trigger CoW if needed.
#[derive(Debug)]
pub struct MemoryRegion {
    /// Base virtual address of this region.
    base: u64,
    /// Total size of the region in bytes.
    size: usize,
    /// Pages containing the region's data (each page is 4KB).
    pages: Vec<Page>,
    /// Section information for PE images (for per-section protection).
    sections: Option<Arc<[SectionInfo]>>,
    /// Human-readable label for debugging.
    label: String,
    /// Default memory protection for the region.
    protection: RwLock<MemoryProtection>,
    /// Region kind for API compatibility.
    kind: RegionKind,
}

/// The kind of memory region.
///
/// Used to distinguish between different allocation types for operations
/// like `free_unmanaged()` and section-based protection lookups.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RegionKind {
    /// PE image with section-based protection.
    PeImage,
    /// Generic mapped data.
    MappedData,
    /// Unmanaged heap allocation (from `Marshal.AllocHGlobal`, etc.).
    UnmanagedAlloc,
}

impl MemoryRegion {
    /// Creates pages from a byte slice.
    fn pages_from_data(data: &[u8]) -> Vec<Page> {
        let num_pages = data.len().div_ceil(PAGE_SIZE);
        let mut pages = Vec::with_capacity(num_pages);

        for i in 0..num_pages {
            let start = i * PAGE_SIZE;
            let end = (start + PAGE_SIZE).min(data.len());
            let chunk = &data[start..end];
            pages.push(Page::from_slice(chunk));
        }

        pages
    }

    /// Creates a new PE image region.
    ///
    /// # Arguments
    ///
    /// * `base` - The base address to load the image at
    /// * `data` - The image bytes (should be mapped according to PE layout)
    /// * `sections` - Section information for protection lookup
    /// * `name` - Human-readable name for debugging
    #[must_use]
    pub fn pe_image(
        base: u64,
        data: &[u8],
        sections: Vec<SectionInfo>,
        name: impl Into<String>,
    ) -> Self {
        let size = data.len();
        let pages = Self::pages_from_data(data);

        Self {
            base,
            size,
            pages,
            sections: Some(Arc::from(sections.into_boxed_slice())),
            label: name.into(),
            protection: RwLock::new(MemoryProtection::READ_EXECUTE),
            kind: RegionKind::PeImage,
        }
    }

    /// Creates a new mapped data region.
    ///
    /// # Arguments
    ///
    /// * `base` - The base address for the mapping
    /// * `data` - The data to map
    /// * `label` - Human-readable label for debugging
    /// * `protection` - Memory protection flags
    #[must_use]
    pub fn mapped_data(
        base: u64,
        data: &[u8],
        label: impl Into<String>,
        protection: MemoryProtection,
    ) -> Self {
        let size = data.len();
        let pages = Self::pages_from_data(data);

        Self {
            base,
            size,
            pages,
            sections: None,
            label: label.into(),
            protection: RwLock::new(protection),
            kind: RegionKind::MappedData,
        }
    }

    /// Creates a new unmanaged allocation region.
    ///
    /// The region is initialized with zeroes and has read-write protection.
    ///
    /// # Arguments
    ///
    /// * `base` - The base address for the allocation
    /// * `size` - Size of the allocation in bytes
    #[must_use]
    pub fn unmanaged_alloc(base: u64, size: usize) -> Self {
        let num_pages = size.div_ceil(PAGE_SIZE);
        let pages: Vec<Page> = (0..num_pages).map(|_| Page::zeroed()).collect();

        Self {
            base,
            size,
            pages,
            sections: None,
            label: String::from("unmanaged"),
            protection: RwLock::new(MemoryProtection::READ_WRITE),
            kind: RegionKind::UnmanagedAlloc,
        }
    }

    /// Returns the base address of this region.
    #[must_use]
    pub fn base(&self) -> u64 {
        self.base
    }

    /// Returns the size of this region in bytes.
    #[must_use]
    pub fn size(&self) -> usize {
        self.size
    }

    /// Returns the end address (exclusive) of this region.
    #[must_use]
    pub fn end(&self) -> u64 {
        self.base + self.size as u64
    }

    /// Returns `true` if the address falls within this region.
    #[must_use]
    pub fn contains(&self, address: u64) -> bool {
        address >= self.base && address < self.end()
    }

    /// Returns `true` if the entire address range falls within this region.
    #[must_use]
    pub fn contains_range(&self, address: u64, len: usize) -> bool {
        address >= self.base && (address + len as u64) <= self.end()
    }

    /// Returns the default protection flags for this region.
    ///
    /// For PE images, this returns `READ_EXECUTE` as a default, but use
    /// [`protection_at`](Self::protection_at) for accurate per-section protection.
    ///
    /// # Panics
    ///
    /// Panics if the internal `RwLock` is poisoned.
    #[must_use]
    pub fn protection(&self) -> MemoryProtection {
        *self.protection.read().expect("protection lock poisoned")
    }

    /// Sets the protection flags for this region.
    ///
    /// This is used by `VirtualProtect` to change region protection.
    ///
    /// # Panics
    ///
    /// Panics if the internal `RwLock` is poisoned.
    pub fn set_protection(&self, protection: MemoryProtection) {
        *self.protection.write().expect("protection lock poisoned") = protection;
    }

    /// Returns the protection flags for a specific address.
    ///
    /// For PE images, this considers the section containing the address.
    /// Addresses in headers or unmapped areas return `READ` only.
    #[must_use]
    pub fn protection_at(&self, address: u64) -> MemoryProtection {
        if let Some(ref sections) = self.sections {
            // Safe: offset within a memory region always fits in u32
            #[allow(clippy::cast_possible_truncation)]
            let rva = (address - self.base) as u32;
            for section in sections.iter() {
                if rva >= section.virtual_address
                    && rva < section.virtual_address + section.virtual_size
                {
                    return section.protection;
                }
            }
            // Address is in headers or unmapped - read only
            MemoryProtection::READ
        } else {
            self.protection()
        }
    }

    /// Reads bytes from this region.
    ///
    /// # Arguments
    ///
    /// * `address` - The address to read from
    /// * `len` - Number of bytes to read
    ///
    /// # Returns
    ///
    /// `Some(Vec<u8>)` containing the data, or `None` if the read fails.
    #[must_use]
    pub fn read(&self, address: u64, len: usize) -> Option<Vec<u8>> {
        if len == 0 {
            return Some(Vec::new());
        }

        if !self.contains_range(address, len) {
            return None;
        }

        // Safe: offset within a memory region always fits in usize
        #[allow(clippy::cast_possible_truncation)]
        let offset = (address - self.base) as usize;
        let mut result = vec![0u8; len];
        let mut bytes_read = 0;

        while bytes_read < len {
            let current_offset = offset + bytes_read;
            let page_index = current_offset / PAGE_SIZE;
            let page_offset = current_offset % PAGE_SIZE;

            if page_index >= self.pages.len() {
                return None;
            }

            let bytes_in_page = (PAGE_SIZE - page_offset).min(len - bytes_read);
            let page = &self.pages[page_index];

            if page
                .read(
                    page_offset,
                    &mut result[bytes_read..bytes_read + bytes_in_page],
                )
                .is_err()
            {
                return None;
            }
            bytes_read += bytes_in_page;
        }

        Some(result)
    }

    /// Writes bytes to this region.
    ///
    /// This triggers copy-on-write for any pages that haven't been modified yet.
    ///
    /// # Arguments
    ///
    /// * `address` - The address to write to
    /// * `bytes` - The data to write
    ///
    /// # Returns
    ///
    /// `true` if the write succeeded, `false` otherwise.
    pub fn write(&self, address: u64, bytes: &[u8]) -> bool {
        if bytes.is_empty() {
            return true;
        }

        if !self.contains_range(address, bytes.len()) {
            return false;
        }

        // Safe: offset within a memory region always fits in usize
        #[allow(clippy::cast_possible_truncation)]
        let offset = (address - self.base) as usize;
        let mut bytes_written = 0;

        while bytes_written < bytes.len() {
            let current_offset = offset + bytes_written;
            let page_index = current_offset / PAGE_SIZE;
            let page_offset = current_offset % PAGE_SIZE;

            if page_index >= self.pages.len() {
                return false;
            }

            let bytes_in_page = (PAGE_SIZE - page_offset).min(bytes.len() - bytes_written);
            let page = &self.pages[page_index];

            if page
                .write(
                    page_offset,
                    &bytes[bytes_written..bytes_written + bytes_in_page],
                )
                .is_err()
            {
                return false;
            }
            bytes_written += bytes_in_page;
        }

        true
    }

    /// Returns a label/name for this region (for debugging and diagnostics).
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Forks this region, creating an independent copy with CoW semantics.
    ///
    /// The forked region shares unmodified pages with the original.
    /// Only pages that are subsequently modified will be copied.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if a page lock is poisoned.
    pub fn fork(&self) -> Result<Self, EmulationError> {
        let forked_pages: Result<Vec<Page>, EmulationError> =
            self.pages.iter().map(Page::fork).collect();

        Ok(Self {
            base: self.base,
            size: self.size,
            pages: forked_pages?,
            sections: self.sections.clone(),
            label: self.label.clone(),
            protection: RwLock::new(self.protection()),
            kind: self.kind,
        })
    }

    /// Returns the number of pages in this region.
    #[must_use]
    pub fn page_count(&self) -> usize {
        self.pages.len()
    }

    /// Returns the number of pages that have been modified (have local copies).
    #[must_use]
    pub fn modified_page_count(&self) -> usize {
        self.pages
            .iter()
            .filter(|p| p.is_modified().unwrap_or(false))
            .count()
    }

    /// Creates a new region with a different base address.
    ///
    /// This is used by `AddressSpace::map()` to assign a base address to a
    /// region that was created with a placeholder base (e.g., 0).
    ///
    /// The pages are shared via CoW, so this is an efficient operation.
    #[must_use]
    pub fn with_base(self, base: u64) -> Self {
        Self {
            base,
            size: self.size,
            pages: self.pages,
            sections: self.sections,
            label: self.label,
            protection: self.protection,
            kind: self.kind,
        }
    }

    /// Returns `true` if this is a PE image region.
    #[must_use]
    pub fn is_pe_image(&self) -> bool {
        self.kind == RegionKind::PeImage
    }

    /// Returns `true` if this is an unmanaged allocation region.
    #[must_use]
    pub fn is_unmanaged_alloc(&self) -> bool {
        self.kind == RegionKind::UnmanagedAlloc
    }

    /// Returns `true` if this is a mapped data region.
    #[must_use]
    pub fn is_mapped_data(&self) -> bool {
        self.kind == RegionKind::MappedData
    }
}

impl Clone for MemoryRegion {
    fn clone(&self) -> Self {
        // Clone uses fork() internally - will panic if lock is poisoned
        // For fallible cloning, use fork() directly
        self.fork().expect("page lock poisoned during clone")
    }
}

#[cfg(test)]
mod tests {
    use crate::emulation::memory::{
        page::PAGE_SIZE,
        region::{MemoryProtection, MemoryRegion, SectionInfo, ThreadId},
    };

    #[test]
    fn test_memory_region_contains() {
        let region = MemoryRegion::mapped_data(
            0x1000,
            &vec![0u8; 0x100],
            "test",
            MemoryProtection::READ_WRITE,
        );

        assert!(region.contains(0x1000));
        assert!(region.contains(0x10FF));
        assert!(!region.contains(0x1100));
        assert!(!region.contains(0x0FFF));
    }

    #[test]
    fn test_memory_region_read_write() {
        let region = MemoryRegion::mapped_data(
            0x1000,
            &vec![0u8; 0x100],
            "test",
            MemoryProtection::READ_WRITE,
        );

        // Write some data
        assert!(region.write(0x1010, &[0xDE, 0xAD, 0xBE, 0xEF]));

        // Read it back
        let data = region.read(0x1010, 4).unwrap();
        assert_eq!(data, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_memory_region_cross_page_read_write() {
        // Create a region spanning multiple pages
        let region = MemoryRegion::mapped_data(
            0x1000,
            &vec![0u8; PAGE_SIZE * 3],
            "test",
            MemoryProtection::READ_WRITE,
        );

        // Write across page boundary
        let write_addr = 0x1000 + PAGE_SIZE as u64 - 2;
        let data = [1, 2, 3, 4, 5, 6];
        assert!(region.write(write_addr, &data));

        // Read it back
        let read_data = region.read(write_addr, 6).unwrap();
        assert_eq!(read_data, data);
    }

    #[test]
    fn test_memory_region_fork() {
        let region = MemoryRegion::mapped_data(
            0x1000,
            &vec![42u8; 0x100],
            "test",
            MemoryProtection::READ_WRITE,
        );

        // Modify original
        region.write(0x1000, &[100]);

        // Fork
        let forked = region.fork().unwrap();

        // Forked should have the same data
        assert_eq!(forked.read(0x1000, 1).unwrap(), vec![100]);

        // Modify forked
        forked.write(0x1000, &[200]);

        // Original should be unchanged
        assert_eq!(region.read(0x1000, 1).unwrap(), vec![100]);
        assert_eq!(forked.read(0x1000, 1).unwrap(), vec![200]);
    }

    #[test]
    fn test_memory_region_fork_shares_unmodified() {
        let region = MemoryRegion::mapped_data(
            0x1000,
            &vec![0u8; PAGE_SIZE * 4],
            "test",
            MemoryProtection::READ_WRITE,
        );

        // Modify page 0 in original
        region.write(0x1000, &[1, 2, 3, 4]);

        assert_eq!(region.modified_page_count(), 1);

        // Fork
        let forked = region.fork().unwrap();

        // Forked starts with no modifications (inherits parent's state as backing)
        assert_eq!(forked.modified_page_count(), 0);

        // Modify different page in forked
        let page2_addr = 0x1000 + (PAGE_SIZE * 2) as u64;
        forked.write(page2_addr, &[5, 6, 7, 8]);

        // Only 1 page modified in forked (not the one inherited from parent)
        assert_eq!(forked.modified_page_count(), 1);

        // Original still has only 1 modified page
        assert_eq!(region.modified_page_count(), 1);
    }

    #[test]
    fn test_memory_protection() {
        let prot = MemoryProtection::READ_WRITE;
        assert!(prot.contains(MemoryProtection::READ));
        assert!(prot.contains(MemoryProtection::WRITE));
        assert!(!prot.contains(MemoryProtection::EXECUTE));
    }

    #[test]
    fn test_section_info() {
        // Read + Execute section (like .text)
        let section = SectionInfo::new(
            ".text".to_string(),
            0x1000,
            0x2000,
            0x400,
            0x1800,
            0x6000_0020, // CODE | EXECUTE | READ
        );

        assert!(section.protection.contains(MemoryProtection::READ));
        assert!(section.protection.contains(MemoryProtection::EXECUTE));
        assert!(!section.protection.contains(MemoryProtection::WRITE));
    }

    #[test]
    fn test_pe_image_protection_at() {
        let sections = vec![
            SectionInfo::new(".text".to_string(), 0x1000, 0x1000, 0, 0, 0x6000_0020),
            SectionInfo::new(".data".to_string(), 0x2000, 0x1000, 0, 0, 0xC000_0040),
        ];

        let region = MemoryRegion::pe_image(0x10000, &vec![0u8; 0x4000], sections, "test.exe");

        // .text section should be READ | EXECUTE
        let text_prot = region.protection_at(0x11000);
        assert!(text_prot.contains(MemoryProtection::READ));
        assert!(text_prot.contains(MemoryProtection::EXECUTE));
        assert!(!text_prot.contains(MemoryProtection::WRITE));

        // .data section should be READ | WRITE
        let data_prot = region.protection_at(0x12000);
        assert!(data_prot.contains(MemoryProtection::READ));
        assert!(data_prot.contains(MemoryProtection::WRITE));
    }

    #[test]
    fn test_thread_id() {
        assert_eq!(ThreadId::MAIN, ThreadId(0));
        let t1 = ThreadId::new(1);
        assert_eq!(t1.value(), 1);
    }

    #[test]
    fn test_unmanaged_alloc() {
        let region = MemoryRegion::unmanaged_alloc(0x5000, 0x2000);

        assert_eq!(region.base(), 0x5000);
        assert_eq!(region.size(), 0x2000);
        assert_eq!(region.protection(), MemoryProtection::READ_WRITE);

        // Should be zero-initialized
        let data = region.read(0x5000, 16).unwrap();
        assert!(data.iter().all(|&b| b == 0));

        // Should be writable
        assert!(region.write(0x5000, &[1, 2, 3, 4]));
        assert_eq!(region.read(0x5000, 4).unwrap(), vec![1, 2, 3, 4]);
    }
}
