//! Change tracking infrastructure for CIL assembly modifications.
//!
//! This module provides comprehensive change tracking capabilities for .NET assembly
//! modifications, supporting both metadata table changes and heap additions. It enables
//! efficient sparse modification tracking with minimal memory overhead.
//!
//! # Key Components
//!
//! - [`crate::cilassembly::changes::AssemblyChanges`] - Core change tracking structure for assembly modifications
//! - [`crate::cilassembly::changes::heap::HeapChanges`] - Heap-specific change tracking for metadata heaps
//!
//! # Architecture
//!
//! The change tracking system is designed around sparse storage principles:
//! - Only modified elements are tracked, not entire data structures
//! - Lazy allocation ensures minimal overhead for read-heavy operations  
//! - Changes can be efficiently merged during binary output generation
//! - All four metadata heaps (#Strings, #Blob, #GUID, #US) are fully supported
//!
//! # Usage Examples
//!
//! ```rust,ignore
//! use crate::cilassembly::changes::{AssemblyChanges, HeapChanges};
//! use crate::metadata::cilassemblyview::CilAssemblyView;
//! use std::path::Path;
//!
//! # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
//! // Create change tracker for an assembly
//! let mut changes = AssemblyChanges::new(&view);
//!
//! // Track modifications
//! if changes.has_changes() {
//!     println!("Assembly has {} table modifications",
//!              changes.modified_table_count());
//! }
//! # Ok::<(), crate::Error>(())
//! ```
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::cilassembly::CilAssembly`] - Primary assembly modification interface
//! - [`crate::cilassembly::write`] - Binary output generation system

mod assembly;
mod heap;

pub use assembly::*;
pub use heap::*;
